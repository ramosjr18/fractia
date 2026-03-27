# Network Exposure Module

## Overview

**⚠️ DEVELOPMENT STATUS: This module is currently in development and should be used at your own risk.**

This module performs basic network exposure assessment by detecting listening services and IPv6 configuration. It identifies services bound to global interfaces (`0.0.0.0` and `[::]`) which may be exposed to the network, and checks IPv6 system configuration.

**Context**: Use this module to get an initial view of network-exposed services before applying firewall rules. This is a diagnostic scan that helps identify what needs firewall protection.

**⚠️ WARNING**: This module is incomplete. The `apply` functionality is not implemented. Only `scan` mode is currently functional. Use with caution.

## What This Module Does (Current Capabilities)

- **NET-001**: Detects services listening on `0.0.0.0` (all IPv4 interfaces)
- **NET-002**: Detects services listening on `[::]` (all IPv6 interfaces)  
- **NET-003**: Checks IPv6 system-wide disable status

### Findings Generated

| ID | Severity | Status | Description |
|:---|:---------|:------|:------------|
| **NET-000** | INFO | WARN | Net tools missing (`ss` command not found) |
| **NET-001** | MEDIUM | PASS/WARN | Services listening on `0.0.0.0` |
| **NET-002** | MEDIUM | INFO | Services listening on `[::]` (IPv6) |
| **NET-003** | LOW | PASS/INFO | IPv6 enabled/disabled status |

### Tools Used

- `ss -tuln`: Lists listening TCP/UDP ports (requires `iproute2` package)
- `/proc/sys/net/ipv6/conf/all/disable_ipv6`: Checks IPv6 kernel configuration

## What This Module Does NOT Do (Explicit Limitations)

- **Does NOT verify firewall rules** (does not check if exposed services are protected by UFW/iptables)
- **Does NOT identify service names** (only shows IP:port, not process/service names)
- **Does NOT check for specific vulnerabilities** (does not test if services are exploitable)
- **Does NOT verify service binding** (does not distinguish between localhost-only vs global bindings for services that listen on both)
- **Does NOT check external accessibility** (does not test if ports are reachable from outside)
- **Does NOT detect port forwarding or NAT** (only checks local listening sockets)
- **Does NOT check for hidden services** (only detects services visible via `ss`)
- **Does NOT provide remediation** (scan-only, no apply functionality)
- **Does NOT integrate with firewall module** (does not correlate findings with firewall rules)
- **Does NOT classify services** (does not distinguish between critical/internal/expected services like `secure-vps` module does)

## Scan Behavior

When executing `ironbase scan --module network`:

1. Checks for `ss` command availability (fails gracefully with NET-000 if missing)
2. Executes `ss -tuln` to list all listening TCP/UDP ports
3. Filters for services bound to `0.0.0.0` (all IPv4 interfaces)
4. Filters for services bound to `[::]` (all IPv6 interfaces)
5. Checks `/proc/sys/net/ipv6/conf/all/disable_ipv6` for IPv6 status
6. Reports findings with evidence (first 3 lines of listening services)

**Output**: Findings displayed on console with truncated evidence. Full details available in module log file.

**Exit Code**: Always returns 0 (scan completes successfully even if exposed services found)

**Dependencies**: Requires `ss` command (from `iproute2` package). Module will report missing dependency but will not fail.

## Apply Behavior

**Not Applicable**: This module does not implement `module_apply()`. The function exists but is a no-op (`:`).

This is a **scan-only diagnostic module**. Remediation must be performed using other modules or manual intervention:
- Use `firewall` module to add UFW rules
- Use `secure-vps` module for comprehensive service exposure assessment
- Manually bind services to `127.0.0.1` if remote access not needed

## Safety Notes

- **Read-only operation**: Only queries network stack state. No modifications performed.
- **No network traffic**: Does not send packets or probe services.
- **No lockout risk**: Scanning listening ports cannot cause connectivity issues.
- **May show false positives**: Services bound to `0.0.0.0` may be protected by firewall rules (use `firewall` module to verify)
- **Limited depth**: Only shows first 3 lines of evidence for brevity

**When NOT to use**: This module provides basic exposure detection. For comprehensive service exposure analysis with firewall correlation, use the `secure-vps` module instead.

## Usage Examples

### Basic Scan

```bash
./cmd/ironbase scan --module network
```

### Integrated with Profile

```bash
./cmd/ironbase scan --profile profiles/ubuntu-baseline.yaml
```

### Expected Output

```
[WARN] [MEDIUM] Global Listeners (IPv4) (NET-001)
      Description: Services are listening on 0.0.0.0 (all interfaces).
      Evidence: tcp  0.0.0.0:22  ...
      Remediation: Bind services to localhost (127.0.0.1) if remote access is not needed.
```

## Status

**State**: ⚠️ **IN DEVELOPMENT** - Use at your own risk

**⚠️ IMPORTANT**: This module is currently in development. Only scan functionality is implemented. Apply mode is not available and will not perform any actions.

**Features Implemented**:
- IPv4 global listener detection
- IPv6 global listener detection
- IPv6 system status check
- Graceful handling of missing tools

**Features Pending**:
- Service name identification (process/service mapping)
- Firewall rule correlation
- Service classification (critical/internal/expected)
- External accessibility testing
- Port forwarding/NAT detection
- Apply/remediation functionality (NOT IMPLEMENTED)
- Integration with firewall module

**⚠️ DISCLAIMER**: This module is provided as-is for experimental use. The scan functionality is stable, but the module is incomplete and should not be used in production environments without thorough testing.
