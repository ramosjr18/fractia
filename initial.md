# Fractia — Security Audit Engine

## Lo que se creó: `/workspace/fractia/`

```
fractia/
├── server.js              # Servidor Express local (puerto 7777)
├── config.js              # Carga .env sin dependencias extras
├── index.html             # UI idéntica a la original (Fractia)
├── .env                   # PROJECT_ROOT apuntando a exampleapp
├── auditors/ (12 módulos)
│   ├── auth.js            # JWT, bcrypt, schemas, OTP
│   ├── api.js             # Rutas sin auth, routes legacy
│   ├── ddos.js            # Rate limits, IP-only keying
│   ├── sql.js             # $queryRaw, tenant scoping
│   ├── xss.js             # CORS, CSRF, reflection
│   ├── secrets.js         # Hardcoded creds, .env débil
│   ├── headers.js         # Helmet, CORP, CSP
│   ├── deps.js            # npm audit real
│   ├── infra.js           # NODE_ENV, trust proxy, body limit
│   ├── bots.js            # CAPTCHA, LoginLog, user-agent
│   ├── crypto.js          # bcrypt rounds, alg confusion
│   └── logs.js            # SecurityLogger/AuditLogger stubs
└── utils/
    ├── fileScanner.js     # Lee archivos reales del proyecto
    └── claudeClient.js    # Enriquecimiento con Claude (deep/full)
```

## Hallazgos reales confirmados

Detecta ahora mismo en ExampleApp: JWT fallback `'default-secret'`, SecurityLogger vacío, AuditLogger vacío, CORS=*, NODE_ENV=development, ruta `/auth/test-email` sin auth, bcrypt OK (12 rounds), `jwt.verify()` sin `algorithms`, y más.

## Para usarlo

```bash
cd /path/to/fractia
node server.js
# Abrir http://localhost:7777
```

Para análisis Deep/Full con Claude real, agregar `ANTHROPIC_API_KEY=sk-ant-...` en `.env`.
Para auditar otro proyecto futuro, cambiar `PROJECT_ROOT` en `.env`.
