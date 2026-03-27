<h1 align="center">IronBase</h1>

<p align="center">
  <strong>A Modular, Future-Proof Linux Hardening Engine.</strong><br>
  <em>Security Scanning • System Hardening • Vulnerability Assessment • Profile-Based Configuration</em><br>
  <br>
  Designed to secure Linux system configuration. Separates hardening logic from orchestration for scalable, safe, and auditable system hardening.
</p>

<p align="center">
    <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/shell-Bash-green?style=flat-square" alt="Shell">
</p>

<p align="center">
  <a href="#what-is-ironbase">About</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-available-modules">Modules</a> •
  <a href="#-documentation">Documentation</a>
</p>

---

## What is IronBase?

IronBase is designed to be the foundational layer for secure Linux system configuration. It separates hardening logic (modules) from orchestration (core), allowing for scalable, safe, and auditable system hardening.

**Key Principles:**
1. **Modularity**: Hardening rules are isolated in self-contained modules.
2. **Safety**: "Scan" mode is read-only and non-destructive by default.
3. **Profile Based**: Define your security posture in simple YAML profiles.
4. **Future Ready**: Architected to evolve from formatted Bash scripts to a compiled high-performance binary without breaking contracts.

---

## ✨ Key Features

| Feature | Description |
|:--------|:------------|
| **🔧 Modular Architecture** | Hardening rules are isolated in self-contained modules. Each module can be run independently or as part of the full suite. |
| **🛡️ Safe Defaults** | "Scan" mode is read-only and non-destructive. Perfect for assessing security posture without making changes. |
| **📋 Profile Based** | Define your security posture in simple YAML profiles. Easy to version control and customize. |
| **🚀 Future Ready** | Architected to evolve from Bash scripts to compiled binaries without breaking contracts. |
| **🔍 Comprehensive Scanning** | Internal (host-based) and external (network simulation) security assessments. |
| **📊 Structured Findings** | Standardized output with severity levels (INFO, LOW, MEDIUM, HIGH, CRITICAL) and actionable recommendations. |
| **⚡ Interactive Remediation** | Safe `apply` mode with backups and safety locks. Prevents accidental lockouts. |
| **📈 Detailed Reporting** | Auto-generated reports with evidence, recommendations, and remediation steps. |
| **🔐 SSH Hardening Wizard** | Interactive step-by-step user creation and root disabling with safety verification. |
| **🐛 Vulnerability Assessment** | Host-based vulnerability scanning using Ubuntu Security Notices (USN) database. |

---

## 🚀 Quick Start

### 1. Scan your system 📊
Run a non-destructive scan to see your current security posture:
```bash
./cmd/ironbase scan
```

### 2. Scan a specific module 🎯
```bash
# SSH Hardening
./cmd/ironbase scan --module ssh

# Secure VPS (Comprehensive Assessment)
./cmd/ironbase scan --module secure-vps

# Vulnerability Assessment
./cmd/ironbase scan --module vulnerability
```

### 3. Apply hardening (Interactive) 🔧
Apply the baseline Ubuntu profile with interactive prompts:
```bash
./cmd/ironbase apply
```

### 4. Apply specific module fixes 🛠️
```bash
# Run Interactive Fixes (Safe by Default)
./cmd/ironbase apply --module secure-vps

# Run Emergency Fixes (Force Mode)
# ⚠️ WARNING: This bypasses safety checks and applies all fixes automatically.
# Use only if you have console access or recovery options.
./cmd/ironbase apply --module secure-vps --force
```

---

## 📦 Available Modules

### 🔒 `secure-vps`
A self-contained module for assessing and securing public VPS instances.

**Capabilities:**
- **Internal Analysis**: Kernel, Users, SSH, Services, Permissions
- **External Simulation**: Exposure check, Public IP, Critical Ports
- **Safe Remediation**: Interactive `apply` mode with backups and safety locks
- **Reporting**: All output saved to `output/runs/<run-id>/` (structured reporting system)

**Usage:**
```bash
# Scan
./cmd/ironbase scan --module secure-vps

# Apply (Interactive)
./cmd/ironbase apply --module secure-vps
```

### 🔐 `ssh`
A focused module for safe SSH hardening with interactive wizard.

**Capabilities:**
- **Comprehensive Scan**: Checks PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords
- **Interactive Wizard**: Step-by-step user creation and root disabling
- **Safety First**: Verified alternative access before blocking root
- **Standalone**: Can be run on any machine independently

**Usage:**
```bash
# Scan SSH configuration
./cmd/ironbase scan --module ssh

# Apply SSH hardening (Interactive)
./cmd/ironbase apply --module ssh
```

### 🐛 `vulnerability`
Host-based vulnerability assessment using Ubuntu Security Notices (USN).

**Capabilities:**
- **Package Vulnerability Scanning**: Matches installed packages against USN database
- **Critical Library Focus**: Prioritizes openssl, sudo, openssh, glibc, polkit
- **Kernel Version Checks**: Identifies EOL and legacy kernels
- **Offline-First Design**: Works without internet using local vulnerability database
- **CI/CD Integration**: Exit codes based on finding severity for pipeline gating

**Usage:**
```bash
# Scan for vulnerabilities (Read-only)
./cmd/ironbase scan --module vulnerability
```

> **Note**: This module is read-only by design. It detects vulnerabilities but does not apply fixes automatically.

### 🔧 Additional Modules

All modules are documented with comprehensive READMEs. Each module includes:
- Overview and context
- What it does (and what it does NOT do)
- Scan and apply behavior
- Safety notes and usage examples
- Current status and pending features

**Available Modules**:
- **`filesystem`**: Filesystem permissions checks (16 checks: ownership, permissions, SUID/SGID binaries, PATH security, with interactive remediation) - [Documentation](modules/filesystem/README.md)
- **`firewall`**: UFW auditing and hardening (11 checks, 3 apply modes: SAFE, FORCE, BOOTSTRAP) - [Documentation](modules/firewall/README.md)
- **`network`**: Network exposure checks (listening ports, IPv6 configuration) - [Documentation](modules/network/README.md)
- **`services`**: Service detection and logging (Docker, auditd, journald) - [Documentation](modules/services/README.md)
- **`ssh`**: SSH hardening wizard (3 checks, interactive user creation) - [Documentation](modules/ssh/README.md)
- **`system`**: System configuration checks (OS version, kernel, time sync, updates) - [Documentation](modules/system/README.md)
- **`users`**: User and privilege checks (UID 0 duplicates, empty passwords, sudoers) - [Documentation](modules/users/README.md)

**Special Features**:
- **`users` module list mode**: `./cmd/ironbase scan --module users --list` - Display all system users with privilege levels (ROOT/SUDO/USER), UID/GID, shell, home directory, and account status
- **`firewall` module fail-fast**: If UFW is inactive, the firewall scan stops after FW-002. Advanced checks (FW-004 through FW-011) are not executed.

---

## 🛠️ Power User Tips

### 📊 Understanding Scan Results
- **Severity Levels**: INFO (informational) → LOW → MEDIUM → HIGH → CRITICAL
- **Status**: PASS (secure), WARN (needs attention), FAIL (vulnerable)
- **Evidence**: Each finding includes evidence and remediation steps

### 🔒 Safe Remediation Workflow
1. **Always scan first**: `./cmd/ironbase scan --module <module>`
2. **Review findings**: Check the generated reports in `output/runs/<run-id>/`
   - `report.json`: Machine-readable findings
   - `report.txt`: Human-readable detailed report
   - `summary.txt`: Executive summary
   - `<module>.log`: Module-specific logs
3. **Apply interactively**: `./cmd/ironbase apply --module <module>` (prompts for each change)
4. **Verify**: Run scan again to confirm fixes

**Note**: All outputs are saved to `output/runs/<run-id>/` to keep project root clean. No artifacts are written to the root directory.

### ⚠️ Force Mode Warning
Force mode (`--force`) bypasses all safety checks:
- ⚠️ **Use only with console access**
- ⚠️ **Have recovery options ready**
- ⚠️ **May cause lockouts if SSH access is not properly configured**

### 📋 Profile Customization
Edit `profiles/ubuntu-baseline.yaml` to customize your security posture:
- Enable/disable specific modules
- Configure module-specific settings
- Version control your security policies

---

## 📚 Documentation

### Architecture Deep Dive
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a comprehensive overview of:
- Design philosophy and internal contracts
- Module system architecture
- Findings Model specification
- Future migration path to compiled binaries

### Module Documentation

All modules include comprehensive technical documentation with:
- Overview and security context
- Current capabilities and explicit limitations
- Scan and apply behavior details
- Safety notes and usage examples
- Status and pending features

**Module READMEs**:
- **[Filesystem Module](modules/filesystem/README.md)**: Filesystem permissions checks
- **[Firewall Module](modules/firewall/README.md)**: UFW auditing and hardening (11 checks, 3 apply modes)
- **[Network Module](modules/network/README.md)**: Network exposure checks
- **[Secure VPS Module](modules/secure-vps/README.md)**: Comprehensive VPS security assessment (dual-perspective)
- **[Services Module](modules/services/README.md)**: Service detection and logging
- **[SSH Hardening Module](modules/ssh/README.md)**: SSH hardening wizard
- **[System Module](modules/system/README.md)**: System configuration checks
- **[Users Module](modules/users/README.md)**: User and privilege checks
- **[Vulnerability Module](modules/vulnerability/README.md)**: Vulnerability assessment guide (read-only)

### Modules Reference
See [modules/README.md](modules/README.md) for detailed information about:
- Available modules and their capabilities
- Finding IDs and their meanings (organized by module)
- Severity classifications
- Remediation guidance

---

## 🏗️ Architecture Overview

```
Profile (YAML) → Core Engine (Bash) → Modules (Bash) → Findings Model → Report
```

**Key Components:**
- **Core Engine** (`core/`): Orchestration, configuration parsing, reporting
- **Findings Model** (`core/findings.sh`): Standardized contract for security results
- **Modules** (`modules/`): Self-contained hardening logic
- **Profiles** (`profiles/`): YAML-based security posture definitions

---

## 🤝 Contributing

IronBase is designed to be modular and extensible. To add a new module:

1. Create a new directory in `modules/`
2. Implement `main.sh` following the module contract
3. Add scanners in `scanners/` if needed
4. Document in `modules/<name>/README.md`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed module contract specifications.

---

## 📄 License

MIT License. Free and Open Source forever.

---

## 👤 Author

**Daniel Ramos**

- GitHub: [@ramosjr18](https://github.com/ramosjr18)
- Website: [danielramos.pro](https://danielramos.pro/)
- LinkedIn: [in/daniel-ramos-camargo](https://www.linkedin.com/in/daniel-ramos-camargo)

---

