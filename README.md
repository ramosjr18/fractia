# Fractia — Security Audit Engine

Fractia es una herramienta de auditoría de seguridad estática diseñada para escanear de forma rápida y automatizada proyectos de Node.js/Express. A diferencia de un simple linter, Fractia se enfoca exclusivamente en vulnerabilidades de seguridad comunes (Top 10 OWASP) y ofrece enriquecimiento opcional de hallazgos utilizando Inteligencia Artificial (Claude de Anthropic).

## 🚀 Características Principales

*   **12 Módulos de Auditoría Integrados**: Analiza autenticación, exposición de secretos, protección contra DDoS, configuración de cabeceras de seguridad, inyecciones de SQL, XSS, dependencias (npm), entre otros.
*   **Enfoque de Dos Capas (Híbrido)**:
    1.  **Análisis Estático Súper Rápido**: Escanea el código en paralelo buscando patrones y vulnerabilidades usando expresiones regulares y parsing de texto.
    2.  **Análisis Profundo con Inteligencia Artificial**: Integración opcional con la API de Anthropic (Claude). La IA recibe los fragmentos de código vulnerables y construye "cadenas de ataque" lógicas para demostrar la explotabilidad y recomendar la remediación exacta.
*   **Aislamiento y Tolerancia a Fallos**: Si un módulo de auditoría falla, el escaneo continúa para los otros 11 módulos, reportando el error aisladamente.
*   **Dashboard Local**: Incluye una sencilla pero elegante interfaz de usuario (HTML/JS) servida localmente para visualizar la puntuación de riesgo (Risk Score), el resumen ejecutivo y los detalles del escaneo.
*   **Privacidad Sensible al Contexto**: Ofusca y trunca dinámicamente (`[REDACTED]`) secretos o tokens reales encontrados antes de presentarlos por pantalla o de enviarlos a evaluar a la IA.

## 🛠️ Requisitos del Sistema

*   Node.js (versión 18+ recomendada)
*   Un proyecto Node/Express de destino a auditar.

## ⚙️ Instalación y Configuración

1. Clona este repositorio o navega hacia la carpeta del proyecto.
2. Instala las dependencias:
   ```bash
   npm install
   ```
3. Crea un archivo `.env` en la raíz de Fractia. Puedes copiar el de ejemplo si existe o crear uno nuevo con las siguientes variables:
   ```env
   # El puerto en el que correrá el dashboard de Fractia
   PORT=7777

   # La ruta absoluta AL PROYECTO QUE VAS A AUDITAR (ej. el directorio raíz del proyecto destino)
   PROJECT_ROOT=/Ruta/Absoluta/A/Tu/Proyecto

   # (Opcional) Clave de la API de Anthropic para auditorías "Deep" o "Full Pentest"
   ANTHROPIC_API_KEY=sk-ant-api03...
   ```

## 💻 Uso

1. Inicia el motor de Fractia:
   ```bash
   npm start
   ```
   *(También puedes usar `npm run dev` si estás modificando auditores y deseas recarga automática con node --watch)*
2. Abre tu navegador y dirígete a: `http://localhost:7777`
3. En el Dashboard, selecciona el modo de escaneo:
   *   **Standard Scan**: Rápido, solo devuelve el análisis estático basado en expresiones regulares de la herramienta. Ideal para CI y desarrollo constante.
   *   **Deep Scan** *(Requiere `ANTHROPIC_API_KEY`)*: Usa Claude para analizar a fondo los hallazgos críticos detectados estáticamente, buscando cómo se podrían explotar de manera más realista.
   *   **Full Pentest** *(Requiere `ANTHROPIC_API_KEY`)*: Modo máximo donde la IA intenta identificar debilidades estructurales complejas y secuencias de ataques de múltiples pasos.
4. Explora el **Risk Score**, los módulos con advertencias/vulnerabilidades, y aplica las recomendaciones provistas en cada alerta.

## 📂 Arquitectura del Proyecto

```text
fractia/
├── server.js              # Servidor principal (Express); orquesta la evaluación en paralelo.
├── config.js              # Carga segura y validación de variables de entorno (PORT, keys).
├── index.html             # UI (Dashboard) de la herramienta.
├── package.json           # Dependencias principales (@anthropic-ai/sdk, cors, express).
├── auditors/              # (12 módulos de auditoría)
│   ├── api.js             # Chequeos de rutas inseguras
│   ├── auth.js            # JWT, manejo de claves, algoritmos débiles
│   ├── bots.js            # Detección de configuración antispam o Rate Limiting.
│   ├── crypto.js          # Rondas de BCrypt y cifrados robustos
│   ├── ddos.js            # Configuración limitadora global
│   ├── deps.js            # Manejo de package.json
│   ├── headers.js         # Helmet, mitigaciones como x-powered-by
│   ├── infra.js           # Revisión de NODE_ENV y tamaño del body de la req.
│   ├── logs.js            # Revisión sobre control de logs sensibles.
│   ├── secrets.js         # Credenciales en duro, secrets de .env, regex para tokens externos.
│   ├── sql.js             # Detección de Raw Queries.
│   └── xss.js             # Medidas anti-Cross Site Scripting.
└── utils/
    ├── fileScanner.js     # Motor robusto para lectura segura de archivos objetivo, esquiva node_modules
    └── claudeClient.js    # Cliente Anthropic de enriquecimiento inteligente.
```

## 📝 Avisos de Confiabilidad y Falsos Positivos

Como herramienta de Análisis Estático híbrida, ten en cuenta lo siguiente:
- Fractia utiliza técnicas de **matching de strings y parsing en texto plano** para encontrar vulnerabilidades rápidas, lo cual podría arrojar *falsos positivos* si el código auditado está formateado de formas no convencionales o usa abstracciones complejas.
- Algunas comprobaciones en los auditores (por ejemplo, en `auth.js`) pueden estar buscando rutas o nombres de variables específicas si la base del script fue adaptada a un proyecto particular. Revise y ajuste las rutas en los auditores según la arquitectura del proyecto auditado!
- Nunca subir a producción la carpeta `fractia` en el proyecto principal; corre la herramienta localmente, en un entorno de QA o de forma aislada.
