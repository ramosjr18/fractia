# Fractia v3.0.0 — Full-Stack Security Platform

## Lo que existe en `/workspace/fractia/`

```
fractia/
├── server.js                   # Express + dual-engine orchestrator (puerto 7777)
├── config.js                   # Carga .env sin dependencias extras
├── index.html                  # Dashboard con tabs Code Audit / Infra Audit
├── package.json                # v3.0.0
├── .env                        # PROJECT_ROOT + API keys
├── auditors/ (12 módulos)      # Code Engine
│   ├── auth.js                 # JWT, bcrypt, schemas, OTP
│   ├── api.js                  # Rutas sin auth, routes legacy
│   ├── ddos.js                 # Rate limits, IP-only keying
│   ├── sql.js                  # $queryRaw, tenant scoping
│   ├── xss.js                  # CORS, CSRF, reflection
│   ├── secrets.js              # Hardcoded creds, .env débil
│   ├── headers.js              # Helmet, CORP, CSP
│   ├── deps.js                 # npm audit real
│   ├── infra.js                # NODE_ENV, trust proxy, body limit
│   ├── bots.js                 # CAPTCHA, LoginLog, user-agent
│   ├── crypto.js               # bcrypt rounds, alg confusion
│   └── logs.js                 # SecurityLogger/AuditLogger stubs
├── utils/
│   ├── fileScanner.js          # Lee archivos reales del proyecto
│   ├── claudeClient.js         # Enriquecimiento con Claude (deep/full)
│   └── openaiClient.js         # Enriquecimiento con GPT-4o (deep/full)
└── engines/
    ├── ironbaseRunner.js        # Wrapper Node.js que ejecuta IronBase vía Bash
    └── ironbase/ (9 módulos)   # Infra Engine — IronBase
        ├── cmd/ironbase         # CLI de IronBase
        ├── core/                # Engine, findings, reporting, utils
        ├── modules/
        │   ├── secure-vps/     # Evaluación integral VPS (16+ checks)
        │   ├── ssh/             # SSH hardening + wizard
        │   ├── firewall/        # UFW (11 checks)
        │   ├── filesystem/      # Permisos críticos (16 checks)
        │   ├── vulnerability/   # Paquetes + kernel CVEs (USN)
        │   ├── users/           # UID 0, sudoers, passwords vacíos
        │   ├── system/          # OS, kernel, NTP, updates
        │   ├── network/         # Puertos, IPv6, exposición
        │   └── services/        # Docker, auditd, journald
        └── profiles/
            └── ubuntu-baseline.yaml
```

## API Endpoints

| Ruta | Descripción |
|------|-------------|
| `GET /api/health` | Estado y engines disponibles |
| `GET /api/structure` | Estructura del proyecto auditado |
| `GET /api/infra-modules` | Módulos IronBase disponibles |
| `POST /api/audit` | Auditoría de código (Code Engine) |
| `POST /api/infra-audit` | Auditoría de infraestructura (IronBase) |

## Para usarlo

```bash
cd /workspace/fractia
node server.js
# Abre http://localhost:7777
```

- **Tab "Code Audit"**: analiza el proyecto en `PROJECT_ROOT` (Node.js/Express).
- **Tab "Infra Audit"**: ejecuta IronBase en el sistema local.

Para análisis Deep/Full con IA, agregar `ANTHROPIC_API_KEY=sk-ant-...` o `OPENAI_API_KEY=sk-...` en `.env`.

Para auditar otro proyecto, cambiar `PROJECT_ROOT` en `.env`.

## Origen de los proyectos

- **Code Engine**: Fractia original (v1.0.0) — auditor estático Node.js/Express + IA.
- **Infra Engine**: IronBase — motor de hardening Linux en Bash, integrado como submódulo en `engines/ironbase/` y envuelto por `engines/ironbaseRunner.js`.
