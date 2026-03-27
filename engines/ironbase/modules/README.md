# IronBase Modules Reference

This document provides a comprehensive reference for all IronBase modules, their scanning capabilities, findings, and remediation options.

## Overview

IronBase employs a modular architecture where each module focuses on a specific security domain. This document serves as:
- A **quick reference** for finding IDs and their meanings
- An **index** of all available modules
- A **cross-reference** to detailed module documentation

## Available Modules

### Core Modules (Full Scan + Apply)

| Module | Capabilities | Status |
|:-------|:------------|:-------|
| **[Secure VPS](secure-vps/README.md)** | Comprehensive threat exposure assessment (Internal + External scans, 16 findings, interactive remediation with FORCE mode) | ✅ Stable |
| **[SSH](ssh/README.md)** | SSH hardening wizard (3 checks: PermitRootLogin, PasswordAuth, PermitEmptyPasswords, interactive user creation) | ✅ Stable |
| **[Firewall](firewall/README.md)** | UFW auditing and hardening (11 checks, fail-fast on prerequisites, 3 apply modes: SAFE, FORCE, BOOTSTRAP) | ✅ Stable |
| **[Filesystem](filesystem/README.md)** | Filesystem permissions checks (16 checks: ownership, permissions, SUID/SGID binaries, PATH security, interactive remediation) | ✅ Stable |

### Specialized Modules (Scan + Limited/No Apply)

| Module | Capabilities | Status |
|:-------|:------------|:-------|
| **[Vulnerability](vulnerability/README.md)** | Host-based vulnerability assessment using USN database (package and kernel scanning, read-only, no apply support) | ⚠️ Partial |
| **[Users](users/README.md)** | User and privilege checks (UID 0 duplicates, empty passwords, sudoers, list mode available via `--list`) | ⚠️ IN DEVELOPMENT |
| **[System](system/README.md)** | System configuration checks (OS version, kernel, time sync, updates, apply placeholder/non-functional) | ⚠️ IN DEVELOPMENT |
| **[Network](network/README.md)** | Network exposure checks (listening ports, IPv6 configuration, scan-only) | ⚠️ IN DEVELOPMENT |
| **[Services](services/README.md)** | Service detection and logging (Docker, auditd, journald, scan-only) | ⚠️ IN DEVELOPMENT |

## Scan Types

### Internal Scan (Host-Based)
**Focus**: Inspects the local system configuration, file permissions, kernel state, and running services from "inside" the server.  
**Goal**: Identify weak configurations, legacy software, and potential privilege escalation vectors.  
**Modules**: `secure-vps`, `ssh`, `filesystem`, `users`, `system`, `services`

### External Scan (Network Simulation)
**Focus**: Simulates how an attacker views the server from the internet.  
**Goal**: Detect exposed services, public ports, and potential attack surfaces visible to the outside world.  
**Note**: This scan runs locally but uses logic to determine what interfaces are public.  
**Modules**: `secure-vps`, `network`, `firewall`

---

## Complete Findings Reference

The following sections detail all findings organized by module. Each finding includes:
- **Finding ID**: Unique identifier for the check
- **Severity**: INFO, LOW, MEDIUM, HIGH, or CRITICAL
- **Description**: What the check does
- **Risk**: Security implications and remediation guidance

### Secure VPS Module Findings

The `secure-vps` module performs both internal and external scans, generating findings with prefixes `INT-` (internal) and `EXT-` (external).

#### Internal System & Kernel Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **INT-SYS-001** | High/Low/Info | **Kernel Version Check** | Analyzes the running kernel version.<br>• **High**: EOL kernel (< 4.19). Vulnerable to exploits.<br>• **Low**: Legacy but supported (4.x, 5.0-5.14).<br>• **Info**: Modern kernel (OK). |
| **INT-SYS-002** | High | **ASLR Status** | Checks Address Space Layout Randomization.<br>• **Risk**: If disabled/weak, memory corruption exploits are easier. |
| **INT-SYS-003** | High | **World Writable PATH** | Checks if any directory in `$PATH` is writable by everyone.<br>• **Risk**: Privilege escalation (attackers can hijack commands). |

#### Internal User & Authentication Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **INT-USR-001** | **Critical** | **Multiple UID 0 Users** | Checks for users other than `root` with UID 0.<br>• **Risk**: Backdoors or unauthorized root-level accounts. |
| **INT-USR-002** | **Critical** | **Empty Passwords** | Checks `/etc/shadow` for accounts with no password.<br>• **Risk**: Unrestricted access to accounts. |

#### Network & Services Findings (Internal & External)

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **EXT-NET-000** | Info | **Public IP Detection** | Confirms if the server has a detectable public IP. |
| **EXT-NET-002** | High | **Ports Exposed to Internet** | Detects services listening on `0.0.0.0` or public IP.<br>• **Risk**: Services accessible by anyone on the internet. |
| **EXT-NET-003** | Low | **ICMP Echo (Ping)** | Checks if server replies to ping.<br>• **Risk**: Makes server discoverable by scanners (low risk). |
| **EXT-SSH-001** | Medium | **SSH on Port 22** | Checks if SSH is on default port 22 and exposed.<br>• **Risk**: High volume of automated brute-force "noise". |
| **INT-NET-002** | **Critical** | **Critical Internal Services** | *Verified Exposure*. Checks for internal DBs (Redis, MySQL, Mongo) listening publicly without firewall blocks.<br>• **Risk**: Data leak or remote code execution. |
| **INT-NET-002-M** | Info | **Mitigated Services** | Services listening publicly but **blocked by UFW/Firewall**.<br>• **Meaning**: Safe, but binding to localhost is cleaner. |
| **INT-NET-003** | Info | **Expected Services** | Web ports (80, 443) or VoIP ports open.<br>• **Meaning**: Standard operation for a web/app server. |
| **INT-NET-001** | Medium | **Unclassified Services** | Any other service listening publicly not in the allowlist.<br>• **Risk**: Potential unknown exposure. |

For detailed documentation, see [Secure VPS Module README](secure-vps/README.md).

### SSH Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **INT-SSH-001** | High | **SSH Root Login** | Checks `PermitRootLogin` in `sshd_config`.<br>• **Risk**: Brute-force attacks targeting the known `root` user. |
| **INT-SSH-002** | Medium | **SSH Password Auth** | Checks `PasswordAuthentication` in `sshd_config`.<br>• **Risk**: Password guessing/brute-force attacks. Keys are recommended. |
| **INT-SSH-003** | **Critical** | **SSH Empty Passwords** | Checks `PermitEmptyPasswords` in `sshd_config`.<br>• **Risk**: CRITICAL - Allows authentication without passwords. Immediate security risk. |

For detailed documentation, see [SSH Module README](ssh/README.md).

### Firewall Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **FW-001** | High | **UFW Installed** | Verifies UFW package is installed.<br>• **Fail-Fast**: Scan stops if UFW not installed. |
| **FW-002** | High | **UFW Status** | Verifies UFW is active.<br>• **Fail-Fast**: **If UFW is inactive, the firewall scan stops after FW-002.** Advanced checks (FW-004 through FW-011) are not executed. |
| **FW-003** | Medium/High | **Default Incoming Policy** | Verifies default incoming policy is DENY.<br>• **Risk**: If not DENY, services may be exposed unintentionally. |
| **FW-004** | High/Medium | **Specific Allow Rules Exist** | Detects explicit ALLOW IN rules. Verifies SSH port is allowed if listening.<br>• **Risk**: Default deny with no allow rules may lock out legitimate access. |
| **FW-005** | Medium/Low | **Docker / nftables Interference** | Detects Docker service and DOCKER chains. Warns if bypass potential exists.<br>• **Risk**: Docker may bypass UFW rules, exposing ports unintentionally. |
| **FW-006** | High/Medium | **Multiple Firewalls Active** | Detects ufw, firewalld, nftables, and manual iptables.<br>• **Risk**: Multiple firewalls can conflict, causing unpredictable behavior. |
| **FW-007** | High/Medium | **Real Service Exposure (Correlated)** | Parses listening services and correlates with UFW rules.<br>• **Risk**: Services listening on public interfaces without firewall control are exposed to internet. |
| **FW-008** | High/Medium/Low | **Forwarding / NAT Policy** | Checks IPv4/IPv6 forwarding and UFW routed policies.<br>• **Risk**: Forwarding enabled without firewall intent may expose internal networks. |
| **FW-009** | Medium/Low | **Logging & Rate Limiting** | Verifies UFW logging status and detects `limit` rules.<br>• **Risk**: Without logging or rate limits, brute-force attacks may go undetected. |
| **FW-010** | High/Medium | **IPv6 Enforcement** | Verifies IPV6=yes in /etc/default/ufw and IPv6 rules presence.<br>• **Risk**: If IPv6 is enabled system-wide but UFW IPv6 is disabled, IPv6 traffic bypasses firewall. |
| **FW-011** | Medium/Low/Info | **Configuration Drift** | Compares listening ports vs UFW allow rules.<br>• **Risk**: Services listening without corresponding firewall rules indicate configuration drift. |

**Important Fail-Fast Behavior**:
- **FW-001**: If UFW is not installed, scan stops immediately (returns exit code 1).
- **FW-002**: If UFW is inactive, scan stops immediately after reporting FW-002 (returns exit code 1). Advanced checks (FW-004 through FW-011) are **not executed**.
- **Rationale**: Advanced firewall checks are only meaningful when UFW is installed and active. This prevents misleading results from checks that require an active firewall.

For detailed documentation, see [Firewall Module README](firewall/README.md).

### Filesystem Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **FS-001** | High | **/etc Ownership** | Verifies `/etc` directory ownership (must be root).<br>• **Risk**: If not root-owned, unauthorized modifications to system configuration are possible. |
| **FS-002** | High | **World Writable /etc** | Detects world-writable files in `/etc` (recursive, depth 3).<br>• **Risk**: Unauthorized users can modify system configuration files. |
| **FS-003** | High | **/boot Ownership** | Verifies `/boot` directory ownership (must be root, if exists).<br>• **Risk**: If not root-owned, bootloader and kernel files may be compromised. |
| **FS-004** | High | **/root Ownership** | Verifies `/root` directory ownership (must be root, if exists).<br>• **Risk**: If not root-owned, root's home directory may be accessible to unauthorized users. |
| **FS-005** | High | **/var/log Ownership** | Verifies `/var/log` directory ownership (must be root).<br>• **Risk**: If not root-owned, log files may be tampered with or deleted. |
| **FS-006** | High | **/usr/bin Ownership** | Verifies `/usr/bin` directory ownership (must be root).<br>• **Risk**: If not root-owned, system binaries may be replaced with malicious versions. |
| **FS-007** | High | **/usr/sbin Ownership** | Verifies `/usr/sbin` directory ownership (must be root).<br>• **Risk**: If not root-owned, administrative binaries may be compromised. |
| **FS-008** | High | **World Writable /boot** | Detects world-writable files in `/boot` (if exists, depth 2).<br>• **Risk**: Bootloader or kernel files may be modified by unauthorized users. |
| **FS-009** | High | **World Writable /root** | Detects world-writable files in `/root` (if exists, depth 2).<br>• **Risk**: Root's private files may be modified by unauthorized users. |
| **FS-010** | High | **World Writable /var/log** | Detects world-writable files in `/var/log` (depth 2).<br>• **Risk**: Log files may be tampered with or deleted. |
| **FS-011** | Medium | **/etc Permissions** | Verifies `/etc` permissions (should be 755 or stricter).<br>• **Risk**: Overly permissive permissions allow unauthorized access to configuration files. |
| **FS-012** | Medium | **/root Permissions** | Verifies `/root` permissions (should be 700).<br>• **Risk**: Overly permissive permissions allow unauthorized access to root's home directory. |
| **FS-013** | Medium | **/boot Permissions** | Verifies `/boot` permissions (should be 755).<br>• **Risk**: Overly permissive permissions allow unauthorized access to boot files. |
| **FS-014** | High/Medium/Info | **SUID Binaries** | Scans for SUID binaries in system directories. Flags unexpected SUID binaries as security risk.<br>• **Risk**: SUID binaries run with owner privileges. Unexpected SUID binaries may allow privilege escalation if compromised. |
| **FS-015** | Medium | **SGID Binaries** | Scans for SGID binaries in system directories (informational).<br>• **Risk**: SGID binaries run with group privileges. Review for unnecessary SGID binaries. |
| **FS-016** | High | **World Writable PATH Directory** | Detects world-writable directories in PATH.<br>• **Risk**: CRITICAL - Allows privilege escalation. Attackers can write malicious binaries to PATH directories and hijack commands. |

For detailed documentation, see [Filesystem Module README](filesystem/README.md).

### Network Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **NET-000** | Info | **Net Tools Missing** | Checks if `ss` command is available.<br>• **Risk**: Cannot perform network scanning without net tools. |
| **NET-001** | Medium | **Global Listeners (IPv4)** | Detects services listening on `0.0.0.0` (all IPv4 interfaces).<br>• **Risk**: Services accessible from any network interface. |
| **NET-002** | Medium | **Global Listeners (IPv6)** | Detects services listening on `[::]` (all IPv6 interfaces).<br>• **Risk**: Services accessible via IPv6 from any network interface. |
| **NET-003** | Low | **IPv6 Status** | Checks IPv6 system-wide disable status.<br>• **Info**: IPv6 enabled/disabled status (informational). |

For detailed documentation, see [Network Module README](network/README.md).

### Services Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **SVC-001** | Info | **Docker Installed** | Detects Docker installation (presence or absence).<br>• **Info**: Reports Docker installation status. |
| **SVC-002** | Low | **Docker Socket** | Checks Docker socket permissions (`/var/run/docker.sock`).<br>• **Risk**: Socket permissions determine who can use Docker. |
| **SVC-003** | Medium | **auditd** | Verifies auditd installation and running status.<br>• **Risk**: If not running, system accounting may be incomplete. |
| **SVC-004** | Low | **Journald Persistence** | Checks journald persistence configuration (`/var/log/journal` directory).<br>• **Info**: Persistent logging vs memory-only logging. |

For detailed documentation, see [Services Module README](services/README.md).

### System Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **SYS-001** | Info | **OS Detection** | Detects OS name and version from `/etc/os-release`.<br>• **Info**: System identification (informational). |
| **SYS-002** | Info | **Kernel Version** | Reports current kernel version (`uname -r`).<br>• **Info**: Kernel identification (informational). |
| **SYS-003** | Medium | **Time Synchronized** | Verifies system time synchronization status (`timedatectl`).<br>• **Risk**: If not synchronized, time-sensitive operations may fail or logs may be inaccurate. |
| **SYS-004** | High | **System Updates** | Checks for pending system updates (Ubuntu/Debian-specific: `/var/lib/update-notifier/updates-available`).<br>• **Risk**: Unpatched vulnerabilities may be present. |
| **SYS-005** | Medium | **Automatic Updates** | Verifies automatic update configuration (`/etc/apt/apt.conf.d/20auto-upgrades`).<br>• **Risk**: If not configured, security patches may not be applied automatically. |

For detailed documentation, see [System Module README](system/README.md).

### Users Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **USR-001** | **Critical** | **UID 0 Users** | Detects multiple users with UID 0 (superuser privilege).<br>• **Risk**: Multiple root-equivalent accounts indicate backdoors or unauthorized access. |
| **USR-002** | High | **Empty Passwords** | Identifies users with empty passwords (requires root to read `/etc/shadow`).<br>• **Risk**: Accounts with no password allow unrestricted access. |
| **USR-003** | High | **Sudoers NOPASSWD** | Checks for `NOPASSWD` directives in `/etc/sudoers`.<br>• **Risk**: NOPASSWD allows sudo access without password, increasing attack surface. |
| **USR-004** | Medium | **Root Account Locked** | Verifies root account password lock status (Ubuntu standard: locked).<br>• **Info**: Root account lock status (informational, standard for Ubuntu). |

**Note**: The `users` module also supports `--list` mode to display all system users with privilege levels (ROOT/SUDO/USER), UID/GID, shell, home directory, and account status.

For detailed documentation, see [Users Module README](users/README.md).

### Vulnerability Module Findings

| Finding ID | Severity | Check Description | Meaning & Risk |
|:-----------|:---------|:------------------|:---------------|
| **VULN-DB-001** | Info | **Vulnerability DB Outdated** | Warns if vulnerability database is older than configured max age (default: 7 days).<br>• **Risk**: Outdated database may miss recent vulnerabilities. |
| **VULN-DB-002** | Medium | **Vulnerability DB Missing** | Warns if vulnerability database is missing (scan limited but continues).<br>• **Risk**: Limited vulnerability coverage if database missing. |
| **VULN-DB-003** | High | **Vulnerability DB Missing** | Fails if vulnerability database is missing (scan cannot proceed).<br>• **Risk**: Cannot perform vulnerability assessment without database. |
| **VULN-OS-001** | **Critical** | **Package RCE Vulnerability** | Package affected by known Remote Code Execution vulnerability.<br>• **Risk**: CRITICAL - Remote code execution possible. |
| **VULN-OS-002** | High | **Package Privilege Escalation** | Package affected by privilege escalation vulnerability.<br>• **Risk**: HIGH - Privilege escalation possible. |
| **VULN-OS-003** | Medium | **Package Auth Bypass/Leak** | Package affected by authentication bypass or information leak vulnerability.<br>• **Risk**: MEDIUM - Authentication bypass or information disclosure. |
| **VULN-OS-004** | Low | **Package DoS/Minor** | Package affected by Denial of Service or minor vulnerability.<br>• **Risk**: LOW - Service disruption or minor security issue. |
| **VULN-KRN-001** | **Critical** | **End-of-Life Kernel** | Kernel < 4.19 (end-of-life, vulnerable to widely exploitable privesc).<br>• **Risk**: CRITICAL - End-of-life kernel with known vulnerabilities. |
| **VULN-KRN-002** | High/Medium | **Legacy Kernel** | Kernel < 5.15 (legacy, vulnerable to privilege escalation).<br>• **Risk**: HIGH/MEDIUM - Legacy kernel with known vulnerabilities. |
| **VULN-CRT-001** | **Critical** | **OpenSSL Critical Vulnerability** | OpenSSL affected by critical vulnerability.<br>• **Risk**: CRITICAL - Critical library vulnerability. |
| **VULN-CRT-002** | High | **Sudo/Polkit Privesc** | Sudo or Polkit affected by privilege escalation vulnerability.<br>• **Risk**: HIGH - Privilege escalation in critical libraries. |
| **VULN-CRT-003** | Medium/High | **OpenSSH Vulnerability** | OpenSSH affected by vulnerability.<br>• **Risk**: MEDIUM/HIGH - SSH vulnerability. |

**Note**: The vulnerability module is read-only by design. It detects vulnerabilities but does not apply fixes automatically. Remediation must be performed using system package managers.

For detailed documentation, see [Vulnerability Module README](vulnerability/README.md).

---

## How to Run Modules

Modules are executed via the IronBase engine or standalone module entry points. Each module follows the standard contract: `module_scan()` for scanning, `module_apply()` for remediation (if supported).

### Via IronBase Engine

```bash
# Scan all enabled modules
./cmd/ironbase scan

# Scan specific module
./cmd/ironbase scan --module firewall

# Apply fixes interactively
./cmd/ironbase apply --module filesystem

# Apply fixes with force mode (dangerous)
./cmd/ironbase apply --module secure-vps --force
```

### Standalone Execution

Some modules support standalone execution:

```bash
# SSH module standalone
./modules/ssh/standalone.sh

# Secure VPS module standalone
./modules/secure-vps/standalone.sh
```

---

## Module Documentation

Each module includes comprehensive technical documentation with:
- Overview and security context
- Current capabilities and explicit limitations
- Scan and apply behavior details
- Safety notes and usage examples
- Status and pending features

**Module READMEs**:
- [Filesystem Module](filesystem/README.md) - Filesystem permissions checks
- [Firewall Module](firewall/README.md) - UFW auditing and hardening
- [Network Module](network/README.md) - Network exposure checks
- [Secure VPS Module](secure-vps/README.md) - Comprehensive VPS security assessment
- [Services Module](services/README.md) - Service detection and logging
- [SSH Module](ssh/README.md) - SSH hardening wizard
- [System Module](system/README.md) - System configuration checks
- [Users Module](users/README.md) - User and privilege checks
- [Vulnerability Module](vulnerability/README.md) - Vulnerability assessment guide

---

## Severity Classifications

| Severity | Meaning | Action Required |
|:---------|:--------|:----------------|
| **CRITICAL** | Immediate security risk | Fix immediately |
| **HIGH** | Significant security risk | Fix as soon as possible |
| **MEDIUM** | Moderate security risk | Review and fix when convenient |
| **LOW** | Minor security concern | Review for best practices |
| **INFO** | Informational finding | No action required |

## Finding Status

| Status | Meaning |
|:-------|:--------|
| **PASS** | Check passed, system is secure for this finding |
| **WARN** | Potential issue detected, review recommended |
| **FAIL** | Security issue confirmed, remediation required |

---

For detailed module documentation, architecture information, and usage examples, see:
- [Main README](../README.md) - Project overview and quick start
- [Architecture Documentation](../docs/ARCHITECTURE.md) - Technical architecture and design principles
- Individual module READMEs in `modules/<module-name>/README.md`
