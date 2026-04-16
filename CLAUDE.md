# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## IMPORTANT: Read this first

Before doing any work in this repo, read **[PREPRODUCTION_PLAN.md](./PREPRODUCTION_PLAN.md)**.
It contains the full implementation plan for the `fractia preproduction` command (GDP-34 subtasks):
- Full CLI specification with all flags
- 8-phase execution flow (preflight → sandbox setup → SAST → sandbox DAST → prod DAST → IronBase → AI analysis → report)
- New file structure under `engines/sandboxAudit/`
- Calibrated production DAST thresholds
- 12-step implementation order with dependencies
- Acceptance test definition

---

## Running the project

```bash
# Web dashboard
npm run serve        # http://localhost:7777

# Interactive CLI
npm start

# Direct CLI
node fractia.js [command] [options]

# Run audit on a project
node fractia.js --target /path/to/project --mode standard
node fractia.js --target /path/to/project --mode full   # includes AI deep analysis

# Attack Engine (DAST) — requires explicit target authorization
node fractia.js attack --target http://localhost:3000 --profile slowloris --duration 60

# Sandbox lab
node fractia.js sandbox up      # start vulnerable targets
node fractia.js sandbox shell   # shell into tools container
node fractia.js sandbox down

# Tor/OpSec
node fractia.js tor --start
node fractia.js tor --rotate
```

---

## Architecture

```
fractia/
├── fractia.js              # CLI entrypoint — add new top-level commands here
├── server.js               # Express web server for dashboard
├── index.html              # Dashboard UI
├── auditors/               # 15 SAST modules (auth, sql, xss, secrets, etc.)
│   └── *.js                # Each auditor exports a scan function
├── engines/
│   ├── codeAudit.js        # SAST orchestrator — calls all auditors/
│   ├── webAnalyzer.js      # Passive recon (tech stack fingerprinting)
│   ├── ironbase/           # 9 Bash modules for Linux infra hardening
│   │   ├── runner.js       # Executes Bash modules, collects results
│   │   └── modules/        # Individual Bash scripts (ssh, firewall, etc.)
│   ├── dast/               # DAST profiles (slowloris, credential stuffing, etc.)
│   └── sandboxAudit/       # TO BUILD (GDP-34): preproduction orchestrator
│       ├── index.js
│       ├── dockerManager.js
│       ├── projectDetector.js
│       ├── phaseRunner.js
│       ├── reportAggregator.js
│       └── templates/
├── cli/
│   ├── webAnalyzerFlow.js  # Interactive recon CLI
│   └── preproduction.js    # TO BUILD: CLI arg parsing for preproduction command
└── utils/
    ├── fileScanner.js      # Core file grep/traversal engine
    └── projectType.js      # Auto-detects Node.js vs Python projects
```

**Key architectural rule:** Each auditor in `auditors/` is independent. `engines/codeAudit.js` discovers and runs them all. Never call auditors directly from new code — go through `codeAudit.js` or the appropriate engine. The `preproduction` command must call existing engines, not duplicate their logic.

**Project type detection:** `utils/projectType.js` determines if a project is Node.js (Express, Next.js, NestJS) or Python (FastAPI, Flask, Django). SAST modules use this to apply language-specific patterns.

**AI modes:** `standard` → heuristics only. `deep` → AI analyzes individual findings. `full` → AI builds cross-phase attack chains across all engines combined.

---

## Environment variables

```
PORT=7777
PROJECT_ROOT=/path/to/project/to/audit

# Required for deep/full AI modes
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

---

## Key implementation notes

- **IronBase requires root** for `/etc/shadow`, `ufw`, kernel audit access
- **DAST profiles** live under `engines/dast/` — each exports a `run(target, options)` function
- **Sandbox Docker Compose** template lives in `engines/sandboxAudit/templates/` — per-project override via `--compose-file`
- **Calibrated production thresholds** (not binary safe/unsafe): slowloris 20 conn/30s, credential stuffing 8 attempts, spike 30 req/5 concurrent — enough to trigger defenses, not enough to cause outages
- **Risk scoring formula**: SAST 25% + Sandbox DAST 25% + Production DAST 35% + IronBase 15%
