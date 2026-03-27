# Firewall Hardening Module

## Overview

This module provides comprehensive UFW (Uncomplicated Firewall) auditing and hardening capabilities. It performs baseline configuration checks and advanced scan-only assessments of firewall rules, interference detection, and service exposure correlation. The module implements fail-fast behavior to prevent misleading results from advanced checks when UFW is not operational.

**Context**: Use this module to audit and harden firewall configuration on Ubuntu/Debian systems using UFW. This is a critical security module that should run early in any security assessment to ensure network-level protection is in place.

## What This Module Does (Current Capabilities)

### Scan Behavior

Performs 11 comprehensive checks covering:

**Baseline Checks (FW-001 to FW-003)**:
- **FW-001**: Verifies UFW installation (fail-fast if missing)
- **FW-002**: Verifies UFW active status (fail-fast if inactive)
- **FW-003**: Verifies default incoming policy is DENY

**Advanced Checks (FW-004 to FW-011)** - Only execute if UFW is active:
- **FW-004**: Detects explicit ALLOW IN rules (verifies SSH port is allowed if listening)
- **FW-005**: Detects Docker service and DOCKER chains (warns if bypass potential exists)
- **FW-006**: Detects multiple active firewalls (ufw, firewalld, nftables, manual iptables)
- **FW-007**: Correlates listening services with UFW rules (detects exposed services without firewall control)
- **FW-008**: Checks IPv4/IPv6 forwarding and UFW routed policies
- **FW-009**: Verifies UFW logging status and detects `limit` rules
- **FW-010**: Verifies IPv6 enforcement (IPV6=yes in /etc/default/ufw and IPv6 rules presence)
- **FW-011**: Compares listening ports vs UFW allow rules (detects configuration drift)

### Apply Behavior

Implements three distinct apply modes:

**SAFE Mode (Default, Interactive)**:
- Detects SSH listening port dynamically
- Adds explicit `ufw allow <ssh_port>/tcp` only after confirmation
- Warns about multiple firewalls but does NOT disable anything automatically
- Lists exposed services and asks whether to add allow rules (never deny by default)
- Optionally adds rate limiting to SSH after confirmation
- Handles IPv6 by asking user to: 1) Enforce IPv6 rules, 2) Disable IPv6 in UFW, 3) Skip
- Shows final `ufw status verbose`

**FORCE Mode (`--force` flag)**:
- Displays blocking warning requiring explicit confirmation ("yes")
- Enforces UFW as the only firewall (stops and disables nftables service)
- Adds allow rules for SSH (detected port), 80/tcp, and 443/tcp
- Applies rate limiting to SSH
- Denies all other listening ports detected via `ss -lntup`
- Disables IPv6 in UFW unless explicitly already hardened
- Reloads UFW and displays final status

**BOOTSTRAP Mode (`--bootstrap` flag)**:
- Displays blocking warning requiring user to type "BOOTSTRAP" to continue
- Installs UFW if missing (supports apt-get, yum, dnf)
- Adds SSH allow rule BEFORE enabling firewall (prevents lockout)
- Enables UFW
- Sets default policies: deny incoming, allow outgoing
- Handles IPv6 according to FORCE logic
- Detects Docker without modifying (only warns about bypass)
- Detects forwarding and disables ONLY if no Docker/VPN/bridge is detected
- Otherwise skips forwarding disable with warning

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **FW-001** | HIGH | FAIL | UFW not installed (fail-fast) |
| **FW-002** | HIGH | PASS/FAIL | UFW active status (fail-fast if inactive) |
| **FW-003** | MEDIUM/HIGH | PASS/FAIL | Default incoming policy DENY |
| **FW-004** | HIGH/MEDIUM | PASS/WARN | Specific allow rules exist |
| **FW-005** | MEDIUM/LOW | WARN | Docker/nftables interference detected |
| **FW-006** | HIGH/MEDIUM | FAIL/WARN | Multiple firewalls active |
| **FW-007** | HIGH/MEDIUM | FAIL/WARN | Real service exposure (correlated) |
| **FW-008** | HIGH/MEDIUM/LOW | FAIL/WARN/PASS | Forwarding/NAT policy check |
| **FW-009** | MEDIUM/LOW | PASS/WARN | Logging and rate limiting status |
| **FW-010** | HIGH/MEDIUM | WARN/FAIL | IPv6 enforcement status |
| **FW-011** | MEDIUM/LOW/INFO | WARN/PASS | Configuration drift detected |

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT support non-UFW firewalls** (does not configure iptables directly, firewalld, or nftables standalone)
- **Does NOT verify rule effectiveness** (does not test if rules actually block traffic)
- **Does NOT check for firewall bypasses** (does not verify if services bypass firewall via Docker/bridges, only warns)
- **Does NOT scan external accessibility** (does not test if ports are reachable from outside)
- **Does NOT verify firewall rule order** (does not check if specific rules override defaults incorrectly)
- **Does NOT check for conflicting iptables rules** (only checks if nftables service is active, not manual iptables rules)
- **Does NOT provide rule templates** (does not offer predefined rule sets for common services)
- **Does NOT verify firewall logging destination** (only checks if logging is enabled, not where logs go)
- **Does NOT check for rate limiting bypasses** (only verifies limit rules exist, not effectiveness)
- **Does NOT integrate with IDS/IPS** (does not configure intrusion detection/prevention)
- **Does NOT support IPv6 routing rules** (only checks IPv6 forwarding, not routed policies)
- **Does NOT verify firewall persistence** (does not check if rules persist across reboots beyond standard UFW behavior)

## Scan Behavior

When executing `ironbase scan --module firewall`:

### Fail-Fast Design

**Important**: This module implements fail-fast behavior for critical prerequisites:

1. **FW-001 (UFW Installed)**: If UFW is not installed, the scan **stops immediately** after reporting FW-001 and returns exit code 1. No further checks are performed.

2. **FW-002 (UFW Status)**: If UFW is inactive, the scan **stops immediately** after reporting FW-002 and returns exit code 1. Advanced checks (FW-004 through FW-011) are **not executed**.

**Rationale**: Advanced firewall checks (rule analysis, service correlation, interference detection) are only meaningful when UFW is installed and active. Running these checks against an inactive firewall would produce misleading or irrelevant results.

**If UFW is inactive, the firewall scan stops after FW-002.** This demonstrates intentional design maturity and prevents false positives from advanced checks.

### Full Scan (UFW Active)

When UFW is active, all 11 checks execute:
1. Baseline checks (FW-001, FW-002, FW-003)
2. Allow rule detection (FW-004)
3. Docker/nftables interference (FW-005)
4. Multiple firewall detection (FW-006)
5. Service exposure correlation (FW-007)
6. Forwarding/NAT policy (FW-008)
7. Logging and rate limiting (FW-009)
8. IPv6 enforcement (FW-010)
9. Configuration drift (FW-011)

**Output**: Findings displayed on console and registered to global report. No files are modified.

**Exit Code**: Returns 1 if critical failures detected (FW-001, FW-002, FW-006, FW-007, FW-008, FW-010), 0 otherwise.

## Apply Behavior

The module implements three distinct apply modes with different safety levels:

### SAFE Mode (Default, Interactive)

**Activation**: Default mode (no flags)

**Behavior**:
- Prompts for confirmation before every action
- Detects SSH port dynamically from `/etc/ssh/sshd_config` and `ss -lnt`
- Adds SSH allow rule only after explicit confirmation
- Warns about multiple firewalls but does NOT disable them automatically
- Lists exposed services and asks whether to add allow rules (never deny by default)
- Optionally adds rate limiting to SSH after confirmation
- Handles IPv6 with three options: 1) Enforce IPv6 rules, 2) Disable IPv6 in UFW, 3) Skip
- Shows final `ufw status verbose`

**Safety**: High - requires explicit confirmation for all actions. Will not break SSH access.

### FORCE Mode (`--force` flag)

**Activation**: `./cmd/ironbase apply --module firewall --force`

**Behavior**:
- Displays blocking warning explaining all actions
- Requires user to type "yes" to continue
- If confirmed:
  - Enforces UFW as the only firewall (stops and disables nftables service)
  - Adds allow rules for SSH (detected port), 80/tcp, and 443/tcp
  - Applies rate limiting to SSH
  - Denies all other listening ports detected via `ss -lntup`
  - Disables IPv6 in UFW unless already hardened
  - Reloads UFW and displays final status

**Safety**: Low - applies aggressive rules without further confirmation. May lock out services.

**Warning**: Ensure console/VNC access before using FORCE mode. SSH access may be disrupted if port detection fails.

### BOOTSTRAP Mode (`--bootstrap` flag)

**Activation**: `./cmd/ironbase apply --module firewall --bootstrap`

**Behavior**:
- Displays blocking warning explaining initial firewall setup
- Requires user to type "BOOTSTRAP" (all caps) to continue
- If confirmed:
  - Installs UFW if missing (supports apt-get, yum, dnf)
  - Adds SSH allow rule BEFORE enabling firewall (prevents lockout)
  - Enables UFW
  - Sets default policies: deny incoming, allow outgoing
  - Handles IPv6 according to FORCE logic
  - Detects Docker without modifying (only warns about bypass)
  - Detects forwarding and disables ONLY if no Docker/VPN/bridge detected
  - Otherwise skips forwarding disable with warning

**Safety**: Medium - designed for initial setup on new hosts. Requires explicit confirmation.

**Use Case**: Initial firewall hardening on new hosts where no firewall is configured.

## Safety Notes

### General Safety

- **Read-only in scan mode**: Only queries firewall state. No modifications performed.
- **Backup creation**: Apply modes create backups of `/etc/default/ufw` before modifications
- **SSH lockout prevention**: All modes detect SSH port dynamically and add allow rule before enabling firewall (BOOTSTRAP) or as first action (SAFE/FORCE)
- **Idempotency**: Running apply multiple times will not duplicate rules

### SAFE Mode Safety

- **High safety**: Requires explicit confirmation for all actions
- **No automatic denial**: Will not add deny rules automatically
- **No service disruption**: Will not disable other firewalls or services automatically
- **SSH preserved**: SSH port is explicitly allowed before any changes

### FORCE Mode Risks

- **Low safety**: Applies aggressive rules without confirmation after initial warning
- **May lock out services**: Denies all ports except SSH, 80, 443 without verification
- **May disrupt Docker**: Does not account for Docker networking requirements
- **May break VPNs**: Does not detect VPN interfaces before disabling forwarding
- **Firewall enforcement**: Stops and disables nftables service (may conflict with other tools)

**⚠️ Always ensure console/VNC access before using FORCE mode**

### BOOTSTRAP Mode Risks

- **Package installation**: May install UFW if missing (requires package manager)
- **Forwarding disruption**: May disable IP forwarding if Docker/VPN/bridge not detected correctly
- **New host assumption**: Designed for new hosts, may not be suitable for production systems with existing firewall configuration

**When NOT to use**:
- Production systems with existing firewall configuration
- Systems with Docker requiring forwarding
- Systems with VPN/bridge networks requiring forwarding
- Systems without console access

### Known Limitations

- **UFW-only**: Does not support other firewall tools (firewalld, direct iptables, nftables standalone)
- **Docker bypass**: Does not prevent Docker from bypassing UFW rules (only warns)
- **IPv6 complexity**: IPv6 handling may not account for all network configurations
- **Port detection**: SSH port detection may fail in edge cases (fallback to port 22)

## Usage Examples

### Scan

```bash
# Basic scan
./cmd/ironbase scan --module firewall

# With profile
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Apply (SAFE Mode - Default)

```bash
# Interactive mode (default)
./cmd/ironbase apply --module firewall
```

### Apply (FORCE Mode)

```bash
# Force mode with explicit confirmation
./cmd/ironbase apply --module firewall --force

# Output will show:
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !              FORCE MODE: FIREWALL HARDENING                      !
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# WARNING: You have requested FORCE apply for firewall hardening.
# ...
# Confirm FORCE execution (type 'yes' to continue):
```

### Apply (BOOTSTRAP Mode)

```bash
# Bootstrap mode for initial firewall setup
./cmd/ironbase apply --module firewall --bootstrap

# Output will show:
# ==============================================================
#           BOOTSTRAP MODE: INITIAL FIREWALL SETUP
# ==============================================================
# ...
# Type 'BOOTSTRAP' (all caps) to continue:
```

### Expected Scan Output (UFW Inactive)

```bash
$ ./cmd/ironbase scan --module firewall
[INFO] Running module: Firewall Hardening (firewall)
[FAIL] [HIGH] UFW Status (FW-002)
      Description: UFW is inactive. This check validates UFW baseline configuration only. It does not assess full service exposure or rule completeness.
      Remediation: Run 'ufw enable'

[WARN] Module Firewall Hardening: FAILED/ISSUES FOUND
```

**Note**: No advanced checks (FW-004 through FW-011) are executed. The scan stops after FW-002.

### Expected Scan Output (UFW Active)

```bash
$ ./cmd/ironbase scan --module firewall
[INFO] Running module: Firewall Hardening (firewall)
[PASS] [HIGH] UFW Status (FW-002)
[PASS] [MEDIUM] Default Incoming Policy (FW-003)
[PASS] [MEDIUM] Specific Allow Rules Exist (FW-004)
[WARN] [MEDIUM] Docker / nftables Interference (FW-005)
      Description: Docker service is active and appears to manipulate firewall rules (DOCKER chains detected). Docker may bypass or interfere with UFW rules.
      Evidence: Docker active: yes | DOCKER chains found in iptables/nftables
      Remediation: Review Docker networking mode and UFW integration. Consider: Docker may bypass UFW - verify port exposure independently with 'ss -lnt'.
[FAIL] [HIGH] Multiple Firewalls Active (FW-006)
      ...
[OK] Module Firewall Hardening: PASSED
```

## Status

**State**: Stable (Scan Complete, Apply Fully Functional)

**Features Implemented**:
- 11 comprehensive scan checks with fail-fast behavior
- Three apply modes: SAFE (interactive), FORCE (aggressive), BOOTSTRAP (initial setup)
- Dynamic SSH port detection
- Docker/VPN/bridge detection
- IP forwarding handling
- IPv6 configuration management
- Logging and rate limiting
- Idempotent rule application
- Backup creation for configuration files

**Features Pending**:
- Rule template system for common services
- Firewall rule effectiveness testing
- Integration with IDS/IPS
- IPv6 routing rule support
- Firewall persistence verification
- Support for non-UFW firewalls (firewalld, direct iptables)
- External accessibility testing
- Firewall rule order validation
