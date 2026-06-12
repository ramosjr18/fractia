# Fractia — Security Audit Suite

> Unified SAST · DAST · Linux Hardening platform with AI-powered remediation

## What it does

Fractia is a security suite that unifies three critical layers of application and
infrastructure security into a single CLI-first interface:

- **SAST** — Static analysis of source code (Node.js & Python projects) to detect
  vulnerabilities before deployment
- **DAST** — Dynamic scanning against live endpoints (OWASP ZAP, Nuclei, plus custom
  resilience profiles: Slowloris, credential stuffing, form flood, spike test)
- **Hardening** — Automated Linux server hardening via the IronBase engine
  (SSH, firewall, filesystem, network, services, users, system & kernel, vulnerability checks)

The AI layer (Anthropic Claude + OpenAI GPT-4o) analyzes vulnerable code fragments,
suggests exact remediations, and builds cross-phase Red Team attack chains so teams
understand the real-world impact of each finding.

## Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 18+ (ES Modules) |
| Dashboard | Express + vanilla HTML/CSS/JS |
| AI | Anthropic Claude (`@anthropic-ai/sdk`) · OpenAI GPT-4o (`openai`) |
| DAST Engine | OWASP ZAP · Nuclei · custom profiles |
| Hardening | IronBase (Bash modules) |
| Sandbox lab | Docker · Docker Compose |

> Note: the application itself runs on Node.js — Docker is only used to spin up the
> intentionally-vulnerable **sandbox lab** targets, not to run Fractia.

## Modules

```
auditors/                 # 15 SAST modules (auth, sql, xss, secrets, headers, crypto, …)
engines/
├── codeAudit.js          # SAST orchestrator — discovers and runs all auditors/
├── webAnalyzer.js        # Passive recon / tech-stack fingerprinting
├── attack/               # DAST engine
│   ├── index.js
│   └── profiles/         # slowloris, botsStuffing, formFlood, spikeTest, nucleiFuzz, zapScan, recon
├── ironbase/             # Linux hardening (Bash modules)
│   └── modules/          # ssh, firewall, filesystem, network, services, users, system, vulnerability
├── flutter/              # Mobile (Flutter/Dart) static checks
├── autoFix.js            # AI remediation
└── prReviewer.js         # PR review integration
cli/                      # Interactive flows (attack, sandbox, opsec, web analyzer)
utils/                    # fileScanner (grep/traversal) · projectType (Node vs Python detection)
sandbox-lab/              # Dockerized vulnerable targets for safe testing
server.js                 # Express dashboard (http://localhost:7777)
fractia.js                # CLI entrypoint
```

## Quick Start

```bash
git clone https://github.com/ramosjr18/fractia.git
cd fractia
npm install

cp .env.example .env      # add your API keys (optional — only needed for AI modes)

# Interactive CLI
npm start

# Web dashboard → http://localhost:7777
npm run serve
```

### Common commands

```bash
# Audit a project (SAST)
node fractia.js --target /path/to/project --mode standard
node fractia.js --target /path/to/project --mode full      # includes AI deep analysis

# Attack engine (DAST) — requires explicit target authorization
node fractia.js attack --target http://localhost:3000 --profile slowloris --duration 60

# Sandbox lab (Dockerized vulnerable targets)
npm run sandbox:lab:up
npm run sandbox:lab:shell
npm run sandbox:lab:down
```

## Configuration

Environment variables (see `.env.example`):

```env
PORT=7777
PROJECT_ROOT=/path/to/project/to/audit

# Optional — only required for Deep / Full AI modes
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
```

> AI keys are optional. `standard` mode runs heuristics only; `deep` and `full` modes
> send code snippets to the configured provider for richer analysis.

## Requirements

- Node.js 18+
- Bash (IronBase — native on Linux/macOS)
- `root` privileges for infrastructure hardening (`/etc/shadow`, `ufw`, kernel audit)
- Docker (only for the sandbox lab)

## Contributing

This repo uses branch protection on `master`. All contributions must go through a Pull
Request with at least 1 approval. Please fork the repo and open a PR from your branch.

## Security note

Run Fractia locally — do not deploy it in production alongside the app it audits.
Only run the attack engine against targets you are explicitly authorized to test.

## License

MIT
