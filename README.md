# Fractia — Full-Stack Security Platform

Fractia es una plataforma de seguridad integral que combina tres engines de análisis: **auditoría de código** (SAST), **pentesting dinámico** (DAST) y **hardening de infraestructura Linux** vía IronBase Engine. Cubre la seguridad desde el sistema operativo hasta el código desplegado en un único dashboard.

---

## Engines

| Engine | Descripción | Módulos | Tecnología |
|--------|-------------|---------|------------|
| **Code Engine (SAST)** | Análisis estático + IA (Node.js & Python) | 13 | JavaScript (ES Modules) |
| **Attack Engine (DAST)** | Pruebas dinámicas de denegación de servicio | 2 | Node.js (CLI-only) |
| **Infra Engine (IronBase)** | Hardening y auditoría de servidores Linux | 9 | Bash |

---

## Características Principales

- **Multi-Lenguaje**: Soporte nativo para proyectos **Node.js (Express, Next.js, NestJS)** y **Python (FastAPI, Flask, Django)**.
- **24 módulos de seguridad** en total: 13 de código, 9 de infraestructura y 2 de ataque dinámico.
- **Dashboard Dual**: Code Audit e Infra Audit con interfaz diferenciada y visualización de riesgos en tiempo real.
- **Análisis Híbrido**: Análisis estático rápido enriquecido con **IA profunda** (Claude 3.5 Sonnet o GPT-4o) para construir vectores de ataque.
- **IronBase Engine**: Ejecuta módulos Bash de bajo nivel para auditar SSH, Firewall, Filesystem, y vulnerabilidades de kernel.
- **DAST Integrado**: CLI para ejecutar ataques de Slowloris y Credential Stuffing contra endpoints activos.
- **Tolerancia a fallos**: Ejecución modular aislada; si un auditor falla, el reporte general continúa.

---

## Requisitos del Sistema

- Node.js 18+
- Bash (para IronBase — nativo en Linux/macOS)
- Para auditoría de infraestructura: Ejecutar con permisos `root` para acceso a `/etc/shadow`, `ufw`, etc.

---

## Instalación y Configuración

```bash
# 1. Clonar e instalar
cd fractia
npm install

# 2. Configurar entorno
cp .env.example .env
```

Editar `.env`:

```env
PORT=7777
PROJECT_ROOT=/ruta/al/proyecto/a/auditar

# IA para modos Deep/Full
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

---

## Uso

### Dashboard Web
```bash
npm run serve
# Abre http://localhost:7777
```

### CLI Interactiva
```bash
npm start
```

### Attack Engine (DAST)
```bash
# Ejemplo de ataque Slowloris
node fractia.js attack --target http://api.local --profile slowloris --duration 60
```

---

## Módulos del Code Engine (SAST)

| Módulo | Qué detecta |
|--------|-------------|
| Autenticación & JWT | JWT fallbacks, algoritmos débiles, hashing inseguro, OTP |
| API Endpoints | Rutas admin sin auth, endpoints de debug, verbos inseguros |
| DDoS & Rate Limiting | Rate limiters ausentes, timeouts de servidor (Slowloris) |
| Inyecciones SQL/NoSQL | $queryRawUnsafe, f-strings en Python, operadores MongoDB |
| XSS & CSRF | CORS wildcard, reflexión de input, eval, innerHTML |
| Secrets & Leaks | +26 patrones de claves (AWS, OpenAI, Stripe, etc.) |
| Headers & CORS | Helmet ausente, HSTS, cookies sin httpOnly/secure |
| Next.js Security | Server Actions inseguras, dangerousSetInnerHTML, middleware |
| Dependencias | CVEs conocidos en npm/pip y auditoría de lockfiles |
| Infraestructura (app) | NODE_ENV, trust proxy, body limits, stack traces |
| Bots & Scraping | CAPTCHA ausente, detección de bots, velocity tracking |
| Criptografía | MD5/SHA1, Math.random(), AES ECB, IVs estáticos |
| Logging & Monitoreo | PII en logs, loggers no estructurados, traceId |

---

## Arquitectura

```text
fractia/
├── server.js                  # Orquestador Web Express
├── fractia.js                 # Entrypoint CLI interactivo
├── index.html                 # Dashboard moderno (Vanilla CSS/JS)
├── auditors/                  # 13 auditores modulares (SAST)
│   ├── auth.js                # Soporta Node.js y Python
│   ├── sql.js                 # Soporta Prisma, SQLAlchemy, etc.
│   ├── nextjs.js              # Auditoría específica Next.js
│   └── ...
├── utils/
│   ├── fileScanner.js         # Motor de escaneo y grep
│   └── projectType.js         # Detección automática Node/Python
└── engines/
    ├── codeAudit.js           # Lógica central del Code Engine
    └── ironbase/              # Engine de infraestructura (Bash)
```

---

## Roadmap 🚀

- [ ] **Mobile Engine**: Auditoría estática para **Flutter/Dart** (fuga de tokens en SharedPreferences, SSL Pinning).
- [ ] **Cloud Engine**: Módulo para auditar configuraciones de AWS S3 y buckets públicos.
- [ ] **Reportes PDF**: Generación de reportes ejecutivos listos para entrega.

---

## Notas de Seguridad

- **Uso Local**: No despliegues Fractia en producción junto a la app que audita.
- **Privacidad**: Los secretos detectados son omitidos o redactados antes de ser procesados por la IA.

