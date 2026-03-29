# Guía de Uso de Fractia 🛡️

Fractia es una plataforma integral de seguridad ofensiva y defensiva. Cubre seis pilares que auditan tu aplicación desde el código fuente hasta cómo se comporta en la red, pasando por el historial de git, apps móviles Flutter, y la corrección automática de vulnerabilidades.

---

## 🏗️ Preparación y Arranque

### Variables de entorno (`.env`)

```env
PORT=7777
PROJECT_ROOT=/ruta/absoluta/a/tu/proyecto

# IA — al menos uno para modos Deep/Full y Auto-Fix
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# GitHub — para Auto-Fix (PR) y Review PR
GITHUB_TOKEN=ghp_...
```

### Iniciar en modo interactivo (CLI)

```bash
cd fractia
node fractia.js
```

Fractia muestra el menú principal con los seis pilares. La primera vez te pedirá seleccionar el proyecto a auditar.

### Iniciar la Web UI

```bash
node fractia.js serve
# Abre http://localhost:7777
```

---

## Menú Principal

```
[1]  Code Audit       — SAST estático · 14 módulos
[2]  Infra Audit      — IronBase · hardening Linux
[3]  Attack  DAST     — recon · spike-test · slowloris · bots-stuffing · form-flood
[4]  Mobile Audit     — Flutter/Dart · 10 módulos
[5]  Auto-Fix   AI    — corrige critical/high · crea branch · abre PR
[6]  Review PR  Shift-Left — audita un PR de GitHub antes del merge
[c]  Configuración
[s]  Iniciar Web UI
[p]  Cambiar proyecto
[q]  Salir
```

---

## 🔍 Pilar A — Code Audit (SAST)

*Corre después de programar y antes de hacer commit.*

Analiza el código fuente del proyecto en `PROJECT_ROOT` buscando vulnerabilidades OWASP Top 10 y patrones peligrosos.

### Módulos disponibles (14)

| Módulo | Qué detecta |
|--------|-------------|
| `auth` | JWT sin `algorithms`, falta de revocación, refresh tokens |
| `api` | Rutas sin autenticación, rutas legacy expuestas |
| `ddos` | Rate limits, IP-only keying, ausencia de throttling |
| `sql` | `$queryRaw` inseguro, falta de tenant scoping |
| `xss` | CORS permisivo, CSRF, reflection de parámetros |
| `secrets` | Credenciales hardcodeadas, `.env` débil, `.gitignore` incompleto |
| `headers` | Helmet, CSP, CORP, X-Frame-Options |
| `deps` | `npm audit` real — CVEs activos en dependencias |
| `infra` | `NODE_ENV`, `trust proxy`, body limit, puertos |
| `bots` | CAPTCHA, LoginLog, User-Agent anomalías |
| `crypto` | bcrypt rounds, confusion de algoritmos |
| `logs` | SecurityLogger/AuditLogger stubs faltantes |
| `nextjs` | Configuraciones inseguras específicas de Next.js |
| `gitHistory` | **Secretos en el historial de git** (ver Pilar G) |

### Profundidades de análisis

- **Standard** — análisis estático puro con regex, rápido, sin IA.
- **Deep** — static + la IA analiza los fragmentos sospechosos y elimina falsos positivos.
- **Full** — deep + la IA construye cadenas de ataque completas con pasos y payloads concretos.

### Cómo usarlo

Selecciona `[1]` en el menú. Elige el grupo de módulos o todos. Elige profundidad. El reporte JSON se guarda en `reports/`.

---

## ⚙️ Pilar B — Infra Audit (IronBase)

*Corre en VPS nuevos o antes de exponer un servidor a Internet.*

Ejecuta IronBase (motor Bash interno) sobre el servidor donde corre Fractia. Revisa el sistema operativo, no el código.

### Módulos IronBase (9)

`secure-vps` · `ssh` · `firewall` · `filesystem` · `vulnerability` · `users` · `system` · `network` · `services`

### Cómo usarlo

Selecciona `[2]` en el menú. Para auditoría completa, arranca con permisos elevados:

```bash
sudo node fractia.js
```

Detecta: puerto SSH por defecto (22), UFW apagado, usuarios con contraseñas vacías, paquetes con CVEs activos, Docker socket expuesto, kernel desactualizado.

---

## 🏴‍☠️ Pilar C — Attack / DAST

*Corre contra staging o producción con cuidado. Nunca en horario pico.*

Ataca tu aplicación viva simulando un hacker externo. Todos los perfiles se ejecutan desde el menú `[3]` o por CLI directo.

### Perfiles disponibles

#### `recon` — Reconocimiento pasivo
No genera tráfico agresivo. Solo HEAD requests.

```bash
fractia attack --target https://api.ejemplo.com --profile recon
```

Detecta: headers de seguridad ausentes (HSTS, CSP, X-Frame-Options…), rutas sensibles expuestas (`.env`, `.git/HEAD`, `/admin`, `/graphql`, `phpinfo.php`…), tech stack fingerprinting, CORS con origins maliciosos, info leak en Server/X-Powered-By.

---

#### `spike-test` — Ráfaga concurrente
Valida si tu rate limiting aguanta bajo carga real.

```bash
fractia attack --target https://api.ejemplo.com --profile spike-test
fractia attack --target https://api.ejemplo.com --profile spike-test --requests 1000 --method POST
```

Envía N requests concurrentes con User-Agents rotatorios. Mide p50/p95/p99, req/s, y detecta el primer request donde el servidor empezó a bloquear (429/403).

---

#### `slowloris` — Agotamiento de conexiones TCP
Valida que el servidor cierre conexiones inactivas correctamente.

```bash
fractia attack --target https://api.ejemplo.com --profile slowloris
fractia attack --target https://api.ejemplo.com --profile slowloris --connections 200 --duration 60
```

---

#### `bots-stuffing` — Credential Stuffing
Valida que el lockout y el rate limit por usuario funcionen.

```bash
fractia attack --target https://api.ejemplo.com --profile bots-stuffing
fractia attack --target https://api.ejemplo.com --profile bots-stuffing --login-path /api/auth/login
```

---

#### `form-flood` — Ataque a formularios web

El perfil más completo. Cinco modos independientes:

| Modo | Qué prueba |
|------|-----------|
| `flood` | Rate limiting del formulario bajo carga |
| `user-enum` | Si el servidor diferencia "usuario no existe" de "contraseña incorrecta" |
| `stuffing` | Envío de credenciales conocidas (CSRF-aware) |
| `spam` | Flooding de datos aleatorios — spam protection |
| `inject` | Payloads SQLi, XSS, SSTI, path traversal en cada campo |
| `all` | Ejecuta los 5 modos en secuencia con reporte consolidado |

```bash
# Formulario con HTML estático (Fractia lo descubre solo)
fractia attack --target https://ejemplo.com/contacto --profile form-flood --mode all

# Formulario SPA/React (sin <form> en el HTML)
fractia attack --target https://ejemplo.com/contacto --profile form-flood \
  --mode inject \
  --form-action https://api.ejemplo.com/contact \
  --fields "name,email,message"

# Solo inyección, formulario específico
fractia attack --target https://ejemplo.com --profile form-flood \
  --mode inject \
  --form-index 2
```

---

## 📱 Pilar D — Mobile Audit (Flutter/Dart)

*Análisis estático de proyectos Flutter. No necesita ejecutar Dart ni tener el SDK instalado.*

Selecciona `[4]` en el menú. Fractia detecta automáticamente si el proyecto actual es Flutter (busca `pubspec.yaml` + `lib/`). Si no, te pide la ruta al proyecto Flutter.

### Módulos disponibles (10)

| Módulo | Qué detecta |
|--------|-------------|
| `auth` | Tokens en SharedPreferences, falta de flutter_secure_storage, sin refresh token, sin session timeout |
| `network` | Sin certificate pinning, llamadas HTTP sin TLS, Dio sin interceptors, sin timeouts |
| `storage` | Datos sensibles en SharedPreferences, android:allowBackup=true, caché local sin cifrar |
| `deeplinks` | Casts inseguros de argumentos de ruta, rutas sin auth guards, deep links sin validación de scheme/host |
| `crypto` | `Random()` predecible, MD5/SHA1, claves AES hardcodeadas, IV estático, modo ECB |
| `platform` | Android: allowBackup, debuggable=true, falta Network Security Config, permisos peligrosos. iOS: ATS desactivado, privacy keys faltantes |
| `deps` | Paquetes vulnerables o desactualizados en pubspec.yaml, paquetes de seguridad ausentes |
| `obfuscation` | Falta `--obfuscate` en build scripts, minifyEnabled=false, assets sensibles sin cifrar |
| `logging` | `print()` con datos sensibles, logs sin kDebugMode guard, stack traces expuestos |
| `state` | Estado de usuario no limpiado al hacer logout, auth state sin stream reactivo, datos sensibles en estado global |

El reporte JSON se guarda en `reports/<proyecto>_mobile_<timestamp>.json`.

---

## 🤖 Pilar E — Auto-Fix Agent

*Requiere IA configurada (ANTHROPIC_API_KEY u OPENAI_API_KEY). GitHub token opcional para abrir la PR automáticamente.*

Selecciona `[5]` en el menú. El agente:

1. Corre el Code Audit completo sobre el proyecto actual.
2. Por cada módulo con severidad `critical` o `high`, manda el archivo real al LLM.
3. La IA devuelve el archivo completo corregido aplicando el **cambio mínimo necesario** — sin refactoring, sin renombrar variables.
4. Escribe los archivos corregidos en disco.
5. Crea un branch `sec-fix-<timestamp>`, hace commit de todos los cambios.
6. Si tienes `GITHUB_TOKEN` y proporcionas el repo, hace push y abre la PR en GitHub automáticamente con una tabla de vulnerabilidades corregidas.

Los casos donde la IA no puede corregir con seguridad sin contexto adicional quedan marcados con `// TODO(Fractia): revisar manualmente — <razón>`.

> **Importante:** revisa siempre el diff antes de hacer merge. El Auto-Fix es una primera pasada, no un sustituto de la revisión humana.

---

## 🔀 Pilar F — Review PR (Shift-Left)

*Audita un Pull Request de GitHub antes de que llegue a `main`. Requiere `GITHUB_TOKEN`.*

### Desde el menú

Selecciona `[6]`, introduce el repo (`owner/repo`), el número de PR, y si quieres publicar el review en GitHub o solo ver los resultados localmente (dry-run).

### Desde CLI (ideal para GitHub Actions)

```bash
fractia review-pr --repo owner/repo --pr 42
fractia review-pr --repo owner/repo --pr 42 --dry-run          # sin publicar
fractia review-pr --repo owner/repo --pr 42 --token ghp_xxx    # token explícito
```

El exit code es `0` si no hay critical/high, `1` si los hay — útil para bloquear el merge en CI:

```yaml
# .github/workflows/security.yml
- name: Fractia Security Review
  run: node fractia.js review-pr --repo ${{ github.repository }} --pr ${{ github.event.number }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Qué hace:**
1. Descarga solo los archivos modificados en el PR via GitHub API.
2. Los guarda temporalmente y corre el Code Audit (standard) sobre ellos.
3. Borra el directorio temporal.
4. Si hay `critical` o `high` → publica `REQUEST_CHANGES` (bloquea el merge).
5. Si solo hay `medium` o menos → publica `COMMENT` (informativo, no bloquea).

El review en GitHub incluye tabla de módulos con severidad, risk score total y conteo por nivel.

---

## 🕵️ Pilar G — Git History Secrets Scanner

*Incluido dentro del Code Audit como módulo `gitHistory`.*

Un secret eliminado de un archivo sigue viviendo en el historial de git para siempre. Este módulo lo encuentra.

Se activa automáticamente al seleccionar `gitHistory` o "Todos los módulos" en el Code Audit. No necesita configuración adicional.

**Qué hace:**

- Ejecuta `git log -p` sobre los últimos 1000 commits (con timeout de 30s).
- Parsea solo las líneas añadidas (`+`) en cada diff.
- Aplica los 19 patrones de credenciales del módulo `secrets` (API keys, tokens, connection strings, claves PEM…).
- Por cada hit, verifica si el secreto **todavía existe en `HEAD`** o fue eliminado.
- Deduplica: mismo patrón + mismo archivo = un solo finding.
- Salta archivos de documentación (`.md`), binarios y tests.

**Output de ejemplo:**

```
✗ [HIGH] [Historial Git] JWT signing secret hardcodeado
  commit a3f1c892 · 12 Jan 2025 · autor: dev@empresa.com · archivo: src/auth/tokens.js
  ⚠️  AÚN EXISTE en el código actual
  code: jwt.sign(payload, '[REDACTED]', { expiresIn: '7d' })
```

**Si encuentras un hit:**
1. Rota la credencial inmediatamente — se considera comprometida desde el momento del commit.
2. Usa `git filter-repo` para reescribir el historial.
3. Notifica a todos los colaboradores para que hagan `git pull --rebase`.
4. Añade un pre-commit hook con `detect-secrets` para prevenir que vuelva a ocurrir.

---

## ⚠️ Mejores Prácticas Generales

- **No expongas el puerto 7777 de Fractia a Internet.** Solo en local o mediante túnel SSH.
- Los perfiles DAST agresivos (`spike-test`, `slowloris`, `form-flood --mode all`) pueden tirar contenedores pequeños. Úsalos siempre en **staging**, nunca en producción en horario pico.
- El **Auto-Fix** escribe archivos directamente en disco. Haz `git stash` o trabaja en una rama limpia antes de ejecutarlo si quieres preservar el estado actual.
- El **Review PR** descarga código de GitHub a un directorio temporal que se borra automáticamente al terminar. Nunca persiste código de terceros en tu sistema.
