# Fractia — Full-Stack Security Platform

Fractia es una plataforma de seguridad integral que combina dos engines independientes: **auditoría de código** para proyectos Node.js/Express, e **hardening de infraestructura Linux** vía IronBase Engine. Cubre la seguridad desde el sistema operativo hasta el código desplegado en un único dashboard.

---

## Engines

| Engine | Descripción | Módulos | Tecnología |
|--------|-------------|---------|------------|
| **Code Engine** | Análisis estático + IA de código Node.js/Express | 12 | JavaScript (ES Modules) |
| **Infra Engine (IronBase)** | Hardening y auditoría de servidores Linux | 9 | Bash |

---

## Características Principales

- **21 módulos de seguridad** en total: 12 de código y 9 de infraestructura.
- **Dashboard con dos modos**: Code Audit e Infra Audit, con interfaz diferenciada por engine.
- **Análisis híbrido en el Code Engine**: análisis estático rápido + enriquecimiento profundo con IA (Claude o GPT-4o).
- **IronBase Engine integrado**: ejecuta módulos Bash para auditar SSH, firewall, filesystem, usuarios, red, servicios y vulnerabilidades del sistema.
- **Privacidad**: los secretos detectados se ocultan antes de ser enviados a la IA. El análisis corre en local.
- **Tolerancia a fallos**: si un módulo falla, el resto continúa y el error se reporta de forma aislada.
- **Exportación de reportes**: cada auditoría genera un JSON descargable con todos los hallazgos.

---

## Requisitos del Sistema

- Node.js 18+
- Bash (para IronBase — nativo en Linux/macOS)
- Un proyecto Node.js/Express destino para la auditoría de código
- Para auditoría de infraestructura: ejecutar Fractia en el servidor objetivo (con permisos root para mejores resultados)

---

## Instalación y Configuración

```bash
# 1. Clonar o navegar al directorio
cd fractia

# 2. Instalar dependencias Node.js
npm install

# 3. Configurar variables de entorno
cp .env.example .env
```

Editar `.env`:

```env
# Puerto del dashboard
PORT=7777

# Ruta absoluta al proyecto Node.js a auditar (Code Engine)
PROJECT_ROOT=/ruta/absoluta/al/proyecto/backend

# (Opcional) IA para modos Deep Audit y Full Pentest
ANTHROPIC_API_KEY=sk-ant-...
# o
OPENAI_API_KEY=sk-...
```

---

## Uso

```bash
npm start
# Abre: http://localhost:7777
```

También disponible con auto-reload en desarrollo:

```bash
npm run dev
```

Al iniciar, el CLI preguntará qué proveedor de IA usar (Claude, OpenAI, o ninguno). La elección se guarda en `.env` para la siguiente sesión.

---

## Dashboard

Al abrir `http://localhost:7777` verás dos pestañas:

### Code Audit
Analiza el código fuente de `PROJECT_ROOT` buscando vulnerabilidades OWASP Top 10:

| Módulo | Qué detecta |
|--------|-------------|
| Autenticación & JWT | JWT fallbacks, algoritmos débiles, bcrypt bajo, OTP, MFA |
| API Endpoints | Rutas admin sin auth, endpoints de debug expuestos |
| DDoS & Rate Limiting | Rate limiters ausentes, configuraciones permisivas, Slowloris |
| Inyecciones SQL/NoSQL | $queryRawUnsafe, concatenación, operadores MongoDB |
| XSS & CSRF | CORS wildcard, reflexión de input, eval(), innerHTML |
| Secrets & Leaks | 26 patrones de claves (AWS, OpenAI, Stripe, GitHub, etc.) |
| Headers & CORS | Helmet ausente, HSTS desactivado, cookies sin httpOnly |
| Dependencias | npm audit real + base de paquetes con CVEs conocidos |
| Infraestructura (app) | NODE_ENV, trust proxy, body limit, stack traces expuestos |
| Bots & Scraping | CAPTCHA ausente, detección de bots, velocity detection |
| Criptografía | MD5/SHA1, Math.random() para tokens, AES ECB, IVs estáticos |
| Logging & Monitoreo | Loggers estructurados, datos sensibles en logs, traceId |

Niveles de profundidad:
- **Standard**: Solo análisis estático (rápido, sin IA)
- **Deep Audit**: Estático + IA analiza vulnerabilidades y construye vectores de ataque
- **Full Pentest**: Estático + IA construye cadenas de ataque de múltiples pasos con payloads

### Infra Audit (IronBase Engine)
Audita el servidor Linux donde corre Fractia:

| Módulo | Qué detecta |
|--------|-------------|
| Seguridad VPS | Evaluación integral: kernel, usuarios, SSH, servicios, puertos |
| SSH Hardening | PermitRootLogin, PasswordAuthentication, wizard de usuario seguro |
| Firewall (UFW) | Estado, políticas, conflictos, interferencia Docker |
| Permisos Filesystem | /, /etc, /boot, /root, SUID/SGID, world-writable dirs |
| Vulnerabilidades | Paquetes con CVEs (USN), kernel EOL, OpenSSL, sudo, glibc |
| Usuarios & Privilegios | UID 0 duplicados, contraseñas vacías, sudoers |
| Sistema | OS version, kernel, NTP, estado de actualizaciones |
| Red & Puertos | Puertos en escucha, IPv6, exposición de servicios |
| Servicios | Docker, auditd, journald |

---

## Arquitectura

```text
fractia/
├── server.js                  # Express + orchestrador de ambos engines
├── config.js                  # Carga y validación de .env
├── index.html                 # Dashboard (tabs Code / Infra)
├── package.json               # v3.0.0
├── auditors/                  # 12 auditores del Code Engine
│   ├── auth.js
│   ├── api.js
│   ├── ddos.js
│   ├── sql.js
│   ├── xss.js
│   ├── secrets.js
│   ├── headers.js
│   ├── deps.js
│   ├── infra.js
│   ├── bots.js
│   ├── crypto.js
│   └── logs.js
├── utils/
│   ├── fileScanner.js         # Navegación y grep de archivos fuente
│   ├── claudeClient.js        # Integración Anthropic Claude
│   └── openaiClient.js        # Integración OpenAI GPT-4o
└── engines/
    ├── ironbaseRunner.js       # Wrapper Node.js → IronBase (Bash)
    └── ironbase/               # IronBase Engine completo
        ├── cmd/ironbase        # CLI de IronBase
        ├── core/               # Engine, findings, reporting, utils
        ├── modules/            # 9 módulos Bash de hardening
        └── profiles/           # Perfiles YAML de seguridad
```

### Endpoints API

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/health` | Estado del servidor y engines disponibles |
| GET | `/api/structure` | Estructura del proyecto auditado |
| GET | `/api/infra-modules` | Lista de módulos IronBase disponibles |
| POST | `/api/audit` | Ejecutar auditoría de código |
| POST | `/api/infra-audit` | Ejecutar auditoría de infraestructura |

---

## Notas de Uso

- **Nunca** desplegar Fractia en producción junto al proyecto que audita. Correr en local, QA, o en el servidor de forma aislada.
- Los análisis estáticos pueden producir falsos positivos si el código usa abstracciones complejas o patrones no convencionales.
- La auditoría de infraestructura ejecuta IronBase directamente en el sistema anfitrión. Para resultados completos (especialmente en módulos como `secure-vps` y `firewall`), ejecutar con `sudo`.
- Los resultados se exportan como JSON desde el botón "Exportar Reporte" en el dashboard.
