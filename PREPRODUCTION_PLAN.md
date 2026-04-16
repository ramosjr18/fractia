# Fractia — `preproduction` Command: Implementation Plan

> **Feature:** `fractia preproduction`
> **Purpose:** Full-stack sandboxed security audit that runs every Fractia engine against a local copy of a project AND against real production — with calibrated thresholds to validate real security without causing outages.
> **Jira:** GDP-34 subtasks
> **Status:** Not started

---

## What This Does (Plain Language)

You run one command:

```bash
fractia preproduction \
  --target /path/to/exampleapp \
  --prod-url https://example.com \
  --ai-depth full
```

Fractia then:
1. Spins up a full Docker environment (app + postgres + redis + nginx) with a copy of your project
2. Waits for the app to be healthy
3. Runs **every single audit engine** against the sandboxed environment (code, DAST, infra)
4. Runs **calibrated DAST** against real production (`example.com`) — real tests, safe thresholds
5. Sends everything through AI full-mode for cross-phase attack chain analysis
6. Generates a combined report (JSON + HTML)
7. Tears everything down cleanly

The result: real security assurance across both pre-production and live production, in one automated run.

---

## CLI Specification

### Command

```bash
fractia preproduction [options]
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--target PATH` | Yes | — | Absolute path to the project folder to audit |
| `--prod-url URL` | Yes | — | Production URL to test against (e.g. https://example.com) |
| `--ai-depth` | No | `full` | AI analysis depth: `standard`, `deep`, `full` |
| `--prod-full` | No | false | Run full destructive DAST against production (use in maintenance window only) |
| `--skip-phase PHASE` | No | — | Skip a specific phase: `sast`, `sandbox-dast`, `prod-dast`, `ironbase`, `ai` |
| `--name` | No | folder name | Project name for report labeling |
| `--login-path PATH` | No | `/api/auth/login` | Login endpoint for credential stuffing test |
| `--port PORT` | No | auto-detected | Override app port if auto-detection fails |
| `--start-cmd CMD` | No | auto-detected | Override app start command if auto-detection fails |
| `--keep-sandbox` | No | false | Don't tear down Docker stack after audit (for manual inspection) |
| `--output DIR` | No | `./reports` | Output directory for reports |

### Examples

```bash
# Full audit, production safe mode (default)
fractia preproduction --target /workspace/exampleapp --prod-url https://example.com

# Full audit including destructive prod tests (maintenance window)
fractia preproduction --target /workspace/exampleapp --prod-url https://example.com --prod-full

# Skip ironbase (e.g. Docker not available with root)
fractia preproduction --target /workspace/exampleapp --prod-url https://example.com --skip-phase ironbase

# Custom login path for credential stuffing
fractia preproduction --target /workspace/exampleapp --prod-url https://example.com --login-path /api/auth/login

# Keep sandbox up after audit for manual testing
fractia preproduction --target /workspace/exampleapp --prod-url https://example.com --keep-sandbox
```

---

## Execution Flow (Detailed)

```
fractia preproduction
    │
    ├─ 0. PREFLIGHT CHECKS
    │     ├─ Docker daemon running?
    │     ├─ docker-compose available?
    │     ├─ --target folder exists and is readable?
    │     ├─ --prod-url reachable? (simple GET)
    │     ├─ AI key available (ANTHROPIC_API_KEY or OPENAI_API_KEY)?
    │     └─ Detect project: type, start command, port, migration cmd
    │
    ├─ 1. SANDBOX SETUP
    │     ├─ Create temp working dir: /tmp/fractia-sandbox-{timestamp}/
    │     ├─ rsync project to temp dir (excludes: node_modules, .git, dist, .next)
    │     ├─ Generate .env.sandbox from template + detected values
    │     ├─ Generate docker-compose.sandbox.yml from template
    │     ├─ Build app Docker image
    │     ├─ docker compose up -d (postgres, redis, app, nginx)
    │     ├─ Poll health endpoint until ready (max 120s, 5s intervals)
    │     └─ Log sandbox URL: http://localhost:{PORT}
    │
    ├─ 2. PHASE 1 — SAST (Static Code Analysis)
    │     ├─ Runs against: temp project copy (local files)
    │     ├─ Engines called: codeAudit.js (all 15 modules)
    │     │     auth, api, ddos, sql, xss, secrets, headers, deps,
    │     │     infra, bots, crypto, logs, nextjs, gitHistory, agentic
    │     ├─ AI enrichment: per --ai-depth
    │     └─ Output: phase1_sast_{timestamp}.json
    │
    ├─ 3. PHASE 2 — SANDBOX DAST (Dynamic against sandboxed app)
    │     ├─ Runs against: http://localhost:{PORT}
    │     ├─ Profiles run (full, no limits):
    │     │     ├─ recon        — headers, sensitive paths, fingerprinting
    │     │     ├─ spike-test   — 500 req, high concurrency
    │     │     ├─ slowloris    — 150 connections, 5 min
    │     │     ├─ bots-stuffing — 100 attempts on --login-path
    │     │     ├─ form-flood   — flood + user-enum + inject (XSS/SQLi payloads)
    │     │     ├─ zap-scan     — if ZAP/Docker available (baseline mode)
    │     │     └─ nuclei-fuzz  — if Nuclei binary available
    │     └─ Output: phase2_sandbox_dast_{timestamp}.json
    │
    ├─ 4. PHASE 3 — PRODUCTION DAST (Calibrated against --prod-url)
    │     ├─ Runs against: https://example.com (or --prod-url)
    │     ├─ Default (calibrated — validates defenses without causing damage):
    │     │     ├─ recon        — full (passive, no risk)
    │     │     ├─ spike-test   — 30 req, low concurrency (validates rate limiting trigger)
    │     │     ├─ slowloris    — 20 connections, 30 sec (validates graceful handling)
    │     │     ├─ bots-stuffing — 8 attempts (validates 429/lockout triggers)
    │     │     └─ form-flood   — inject mode, 1 pass (validates WAF/filters)
    │     ├─ With --prod-full (full destructive — maintenance window only):
    │     │     └─ All profiles at full sandbox thresholds
    │     ├─ Always skipped on production:
    │     │     ├─ zap-scan active mode (too invasive)
    │     │     └─ nuclei-fuzz (too invasive)
    │     └─ Output: phase3_prod_dast_{timestamp}.json
    │
    ├─ 5. PHASE 4 — IRONBASE (Infrastructure audit inside sandbox)
    │     ├─ Runs inside: the app Docker container (exec)
    │     ├─ Simulates: what IronBase would find on a real VPS with this setup
    │     ├─ Modules: all 9 IronBase bash scripts
    │     │     secure-vps, ssh, firewall, filesystem, vulnerability,
    │     │     users, system, network, services
    │     ├─ Execution: docker exec -u root {container} bash ironbase_runner.sh
    │     └─ Output: phase4_ironbase_{timestamp}.json
    │
    ├─ 6. PHASE 5 — AI FULL ANALYSIS
    │     ├─ Input: aggregated findings from phases 1–4
    │     ├─ AI task: cross-phase attack chain construction
    │     │     Example chain: "Secret in git history (P1) → hardcoded key works on
    │     │     prod API (P3) → rate limiting absent (P2/P3) → full account takeover"
    │     ├─ Output: prioritized remediation roadmap (critical → low)
    │     └─ Model: Claude full mode or GPT-4o (per config)
    │
    ├─ 7. PHASE 6 — REPORT GENERATION
    │     ├─ Combined JSON: preproduction_{name}_{timestamp}.json
    │     │     Structure: { meta, phases: [P1,P2,P3,P4], ai_analysis, risk_scores }
    │     ├─ HTML report: preproduction_{name}_{timestamp}.html
    │     │     — Phase tabs (SAST / Sandbox DAST / Prod DAST / IronBase)
    │     │     — AI attack chains section
    │     │     — Risk score breakdown
    │     │     — Per-finding remediation
    │     └─ Risk scoring:
    │           phase_score = existing Fractia scoring per phase
    │           overall_score = weighted average (SAST:25% + SandboxDAST:25% + ProdDAST:35% + Infra:15%)
    │           Production gets higher weight because it's the real truth
    │
    └─ 8. TEARDOWN
          ├─ docker compose down (unless --keep-sandbox)
          ├─ Remove temp dir (unless --keep-sandbox)
          └─ Print report path + overall risk score
```

---

## Project Auto-Detection Logic

`projectDetector.js` reads the target folder and infers everything needed:

### Node.js projects
```
package.json exists?
  → Read "scripts.start" or "scripts.dev" for start command
  → Read "main" field for entry point
  → Check for: Express (port in app.listen), Next.js (port 3000), NestJS (port 3000)
  → Check for Prisma: prisma/schema.prisma → migration cmd = "npx prisma migrate deploy"
  → Check for .env.example → use as .env.sandbox template
```

### Python projects
```
requirements.txt OR pyproject.toml exists?
  → Check for uvicorn → start cmd = "uvicorn main:app --host 0.0.0.0 --port 8000"
  → Check for gunicorn → start cmd = "gunicorn main:app"
  → Check for alembic → migration cmd = "alembic upgrade head"
  → Default port: 8000
```

### Detection output schema
```js
{
  type: 'node' | 'python',
  startCmd: 'npm run start',
  port: 3001,
  migrationCmd: 'npx prisma migrate deploy',
  buildCmd: 'npm run build',    // if needed before start
  envTemplate: '.env.example',  // path to copy for sandbox env
  hasDatabase: true,
  databaseType: 'postgres',
  hasRedis: true,
}
```

---

## Docker Compose Template

File: `engines/sandboxAudit/templates/docker-compose.sandbox.yml`

```yaml
# Auto-generated by fractia preproduction — do not edit manually
# Generated: {{TIMESTAMP}}
# Project: {{PROJECT_NAME}}

services:
  app:
    build:
      context: {{PROJECT_PATH}}
      dockerfile: Dockerfile
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://sandbox_user:sandbox_pass@db:5432/sandbox_db
      REDIS_URL: redis://redis:6379
      PORT: {{APP_PORT}}
    ports:
      - "{{APP_PORT}}:{{APP_PORT}}"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:{{APP_PORT}}/health"]
      interval: 5s
      timeout: 10s
      retries: 24   # 120s total wait

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: sandbox_user
      POSTGRES_PASSWORD: sandbox_pass
      POSTGRES_DB: sandbox_db
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sandbox_user"]
      interval: 5s
      timeout: 5s
      retries: 10
    volumes:
      - sandbox_db_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru

  nginx:
    image: nginx:alpine
    ports:
      - "{{NGINX_PORT}}:80"
    volumes:
      - {{NGINX_CONF}}:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - app

volumes:
  sandbox_db_data:

networks:
  default:
    name: fractia_sandbox_{{TIMESTAMP}}
```

### Nginx config template (`templates/nginx.conf`)

```nginx
# Fractia sandbox reverse proxy
upstream app {
    server app:{{APP_PORT}};
}

server {
    listen 80;
    server_name localhost;

    # Security headers (to test IronBase findings)
    # Intentionally minimal — auditing the raw app behavior

    location / {
        proxy_pass http://app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
        proxy_connect_timeout 10s;
    }
}
```

---

## Calibrated Production Thresholds

| Profile | Sandbox | Production (default) | Production (--prod-full) |
|---------|---------|---------------------|--------------------------|
| **recon** | Full | Full | Full |
| **spike-test** | 500 req, 50 concurrent, 30s | 30 req, 5 concurrent, 10s | 200 req, 20 concurrent, 30s |
| **slowloris** | 150 conn, 300s | 20 conn, 30s | 100 conn, 120s |
| **bots-stuffing** | 100 attempts, 10 concurrent | 8 attempts, 2 concurrent | 50 attempts, 5 concurrent |
| **form-flood flood** | 200 submissions | Skip | 50 submissions |
| **form-flood user-enum** | Full | 5 probes | 20 probes |
| **form-flood inject** | Full payload set | 1 pass, all payloads | Full payload set |
| **form-flood spam** | Full | Skip | Skip |
| **zap-scan** | Baseline + active | Skip | Skip |
| **nuclei-fuzz** | Full | Skip | Skip |
| **ironbase** | Against Docker container | Skip | Skip |

**Rationale for production limits:**
- 8 credential stuffing attempts: enough to verify 429 fires before lockout
- 20 Slowloris connections: validates graceful connection handling without exhausting pool
- 30 spike requests: validates rate limiter triggers without causing visible latency
- 1-pass injection: validates WAF/sanitization catches payloads, no amplification
- ZAP/Nuclei skipped on prod: active scanning generates too much noise and can trigger IDS bans

---

## New Files to Create

```
fractia/
├── engines/
│   └── sandboxAudit/
│       ├── index.js              # Main orchestrator — entry point for the command
│       ├── dockerManager.js      # Docker Compose lifecycle management
│       │                             start(), stop(), healthCheck(), execInContainer()
│       ├── projectDetector.js    # Auto-detect: type, port, start cmd, migrations
│       ├── phaseRunner.js        # Sequential phase execution with error isolation
│       │                             runPhase(name, fn) — catches failures per phase
│       ├── reportAggregator.js   # Merges phase JSONs → combined report + HTML
│       └── templates/
│           ├── docker-compose.sandbox.yml  # Compose template (variable placeholders)
│           ├── nginx.conf                   # Nginx reverse proxy template
│           └── .env.sandbox                 # Sandbox environment template
│
├── cli/
│   └── preproduction.js          # CLI argument parsing for the new command
│                                     Reads flags, validates inputs, calls sandboxAudit/index.js
│
└── fractia.js                    # MODIFY: add 'preproduction' to menu + direct CLI handler
```

---

## Integration with Existing Fractia Engines

`sandboxAudit/index.js` calls existing engines directly — **no duplication**:

```js
// Phase 1 — SAST
import { runCodeAudit } from '../codeAudit.js'
await runCodeAudit({ projectPath: sandboxCopyPath, depth: aiDepth })

// Phase 2 — Sandbox DAST
import { runAttack } from '../attack/index.js'
await runAttack({ target: `http://localhost:${port}`, profile: 'recon', ...sandboxThresholds })
await runAttack({ target: `http://localhost:${port}`, profile: 'slowloris', connections: 150 })
// ... all profiles

// Phase 3 — Production DAST
await runAttack({ target: prodUrl, profile: 'recon' })
await runAttack({ target: prodUrl, profile: 'slowloris', connections: 20, duration: 30 })
// ... calibrated thresholds

// Phase 4 — IronBase
import { runIronbase } from '../ironbaseRunner.js'
await runIronbase({ mode: 'docker', containerId: sandboxContainerId })

// Phase 5 — AI Analysis
import { runAIAnalysis } from '../ai/analyzer.js'
await runAIAnalysis({ findings: aggregatedFindings, mode: 'attack-chains' })
```

---

## Sandbox .env Template

File: `engines/sandboxAudit/templates/.env.sandbox`

```env
# Auto-generated sandbox environment
# Override any value by editing before running sandbox-audit

NODE_ENV=production
PORT={{APP_PORT}}

# Database (sandbox postgres container)
DATABASE_URL=postgresql://sandbox_user:sandbox_pass@localhost:5432/sandbox_db

# Redis (sandbox redis container)
REDIS_URL=redis://localhost:6379

# Auth (use test secrets in sandbox — never real prod secrets)
JWT_SECRET=sandbox_jwt_secret_fractia_audit_2024
JWT_REFRESH_SECRET=sandbox_refresh_secret_fractia_audit_2024

# Email (disabled in sandbox)
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=

# Storage (disabled in sandbox)
AWS_S3_BUCKET=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# External APIs (disabled in sandbox — these are NOT tested here, prod DAST covers the real endpoints)
# Add any project-specific vars below
```

---

## HTML Report Structure

```
preproduction_{name}_{timestamp}.html
│
├─ Header: Project name, date, overall risk score (0-100), prod URL
│
├─ Executive Summary
│   ├─ Critical findings count (all phases combined)
│   ├─ Phase risk scores breakdown (SAST: X | Sandbox: X | Prod: X | Infra: X)
│   └─ AI: Top 3 attack chains found
│
├─ Phase 1 — SAST
│   └─ Per-module findings (auth, sql, xss, secrets, etc.)
│
├─ Phase 2 — Sandbox DAST
│   └─ Per-profile results with response data
│
├─ Phase 3 — Production DAST (example.com)
│   └─ Per-profile results — real production behavior
│
├─ Phase 4 — IronBase
│   └─ Per-module: SSH, firewall, filesystem, etc.
│
├─ AI Attack Chains
│   └─ Each chain: Step 1 → Step 2 → Impact → Remediation
│
└─ Remediation Roadmap
    ├─ Critical (fix immediately)
    ├─ High (fix this sprint)
    ├─ Medium (fix next sprint)
    └─ Low (track and monitor)
```

---

## Risk Scoring Formula

```
phase_weight = {
  sast:         0.25,   // Code is the foundation
  sandbox_dast: 0.25,   // What the app does when running
  prod_dast:    0.35,   // Real production behavior (highest weight — it's truth)
  ironbase:     0.15,   // Infrastructure of the container
}

overall_risk = (
  sast_score        * 0.25 +
  sandbox_dast_score * 0.25 +
  prod_dast_score    * 0.35 +
  ironbase_score     * 0.15
)

// Production gets highest weight because if prod passes, you can ship.
// If sandbox passes but prod fails, the sandbox was wrong.
```

---

## Implementation Order & Dependencies

```
Step 1 — CLI entry point
  └─ cli/preproduction.js + fractia.js menu entry
      No deps, start here. Implement arg parsing + validation only.

Step 2 — Project detector
  └─ engines/sandboxAudit/projectDetector.js
      No deps. Implement and test standalone against /workspace/exampleapp.

Step 3 — Docker manager
  └─ engines/sandboxAudit/dockerManager.js
      Deps: Docker installed. Implement start/stop/healthCheck/exec.
      Test with a dummy Node.js app before connecting to real project.

Step 4 — Sandbox setup (tie steps 2+3 together)
  └─ engines/sandboxAudit/index.js (setup section only)
      Use detector output → generate compose file → spin up → health check.
      Test end-to-end with ExampleApp.

Step 5 — Phase runner
  └─ engines/sandboxAudit/phaseRunner.js
      Wraps existing engine calls with error isolation.
      Each phase runs inside try/catch — one failure doesn't stop the audit.

Step 6 — SAST phase (Phase 1)
  └─ Call existing codeAudit.js against the sandbox copy.
      Lowest risk — purely static, no network.

Step 7 — Sandbox DAST (Phase 2)
  └─ Call existing attack engine profiles against localhost.
      Requires sandbox to be running (Step 4 must work first).

Step 8 — Production DAST (Phase 3)
  └─ Same as Phase 2 but with calibrated thresholds and prod URL.
      Test with --skip-phase sandbox-dast first to isolate.

Step 9 — IronBase (Phase 4)
  └─ Run IronBase bash scripts via docker exec inside sandbox container.
      Requires root in container — set in docker-compose.sandbox.yml.

Step 10 — AI analysis (Phase 5)
  └─ Call existing AI analyzer with aggregated phase 1–4 findings.

Step 11 — Report aggregator
  └─ engines/sandboxAudit/reportAggregator.js
      Merge all phase JSONs → combined JSON + HTML report.

Step 12 — Full integration test
  └─ Run `fractia preproduction --target /workspace/exampleapp --prod-url https://example.com`
      Fix any issues. This is the acceptance test.
```

---

## Acceptance Test (Definition of Done)

Running the following command must complete successfully end-to-end:

```bash
fractia preproduction \
  --target /path/to/project \
  --prod-url https://example.com \
  --ai-depth full \
  --login-path /api/auth/login \
  --name exampleapp-audit
```

**Must produce:**
- [ ] Docker sandbox spins up with ExampleApp running on localhost
- [ ] Phase 1 SAST completes across all 15 modules
- [ ] Phase 2 Sandbox DAST hits localhost with all profiles
- [ ] Phase 3 Production DAST hits example.com with calibrated thresholds
- [ ] Phase 4 IronBase runs inside the container
- [ ] Phase 5 AI generates attack chains from combined findings
- [ ] Combined HTML report opens in browser with all phases visible
- [ ] Docker stack is cleaned up after run
- [ ] Overall risk score printed to terminal
- [ ] No phase failure stops the entire run (error isolation works)

---

## System Requirements

| Dependency | Version | Required for |
|-----------|---------|-------------|
| Docker | 24+ | Sandbox container |
| docker compose | v2 | Stack orchestration |
| Node.js | 18+ | Fractia itself |
| Bash | Any | IronBase modules |
| OWASP ZAP | Latest | zap-scan phase (optional) |
| Nuclei | Latest | nuclei-fuzz phase (optional) |
| `curl` | Any | Health checks |
| `rsync` | Any | Project copy to temp dir |
| AI API key | — | Phase 5 AI analysis |

---

## Notes

- **Never run `--prod-full` against a live production with real users without a maintenance window.** Default calibrated mode is safe for anytime use.
- **Sandbox env vars:** The sandbox uses dummy secrets. The goal is to test the app's behavior, not its real credentials. Real credential testing happens via DAST against production endpoints.
- **IronBase on real VPS:** The IronBase phase here audits the Docker container, not the actual production VPS. To audit the real VPS, run `fractia` IronBase engine directly on the server with root access. That is a separate step.
- **ExampleApp-specific:** ExampleApp uses Prisma migrations. The project detector will auto-detect this and run `npx prisma migrate deploy` before starting the app in the sandbox.
