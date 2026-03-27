# Guía de Uso de FractIA 🛡️

FractIA es una plataforma híbrida e integral de seguridad ofensiva y defensiva. Se compone de tres pilares fundamentales que auditan tu aplicación desde el código hasta cómo se comporta en la red (Producción).

---

## 🏗️ 1. Preparación y Arranque (Dashboard)

El núcleo principal de FractIA es un dashboard local desde donde orquestas las auditorías estáticas (Código e Infraestructura).

### Configuración Inicial
Asegúrate de tener definidas tus variables en el `.env`:
```env
PORT=7777
# La ruta absoluta del backend que vas a auditar (ej. ExampleApp-backend o ExampleApp-web)
PROJECT_ROOT=/Ruta/Absoluta/A/Tu/Proyecto
# (Opcional) Token para que la IA elimine los falsos positivos
OPENAI_API_KEY=sk-... 
```

### Ejecutar el Dashboard
```bash
npm install
npm run dev
```
Abre tu navegador en `http://localhost:7777`.

---

## 🔍 2. Pilar A: Auditoría de Código (SAST)
*Ideal para correr DESPUÉS de programar y ANTES de hacer commit.*

Desde el **Dashboard > Pestaña "Code Audit"**, FractIA leerá los archivos de la ruta especificada en `PROJECT_ROOT`. Buscará problemas lógicos y vulnerabilidades de capa de aplicación (OWASP Top 10).

**Cómo usarlo:**
1. Selecciona la profundidad del Escaneo:
   - **Standard**: Análisis rápido estático usando Regex y AST.
   - **Deep Audit**: Sube los fragmentos peligrosos a GPT-4 para confirmación.
   - **Full Pentest**: La IA redacta cadenas de ataque complejas basándose en las brechas encontradas.
2. Presiona **"Auditar"**.
3. Revisa la tabla de vulnerabilidades (Rojo = Crítico). Verás problemas como la falta de CAPTCHAS, Rate Limits globales sin IP-tracking o inyecciones de SQL.
4. Usa el botón **"Exportar Reporte"** para obtener el JSON de la auditoría.

---

## ⚙️ 3. Pilar B: Hardening de Infraestructura (IronBase)
*Ideal para correr en VPS nuevos o antes de exponer un servidor a Internet.*

Desde el **Dashboard > Pestaña "Infra Audit"**, FractIA ejecuta sus módulos internos de Bash (IronBase) para revisar el servidor anfitrión (el servidor donde estás corriendo FractIA en ese momento).

**Cómo usarlo:**
1. Es **altamente recomendado** que arranques FractIA con permisos elevados si quieres auditar a fondo: `sudo npm run dev`.
2. Selecciona los módulos (Firewall, SSH, Permisos, Vulnerabilidades de OS).
3. Presiona **"Ejecutar Auditoría de Infraestructura"**.
4. Te alertará si tienes el puerto SSH por defecto (22), si UFW está apagado o si hay usuarios con contraseñas vacías.

---

## 🏴‍☠️ 4. Pilar C: Pentesting Activo y Red Team (DAST)
*Ideal para correr contra entornos de STAGING o contra Producción (con mucho cuidado).*

Esta es la faceta más agresiva de FractIA. En lugar de leer tu código, ataca tu aplicación viva simulando ser un hacker desde fuera de tu red. A diferencia de los Pilares A y B, esto se ejecuta mediante línea de comandos (CLI).

### Modo 1: Scripts Nativos (Denegación de Servicio y Bots)
Tira peticiones masivas para validar si tus Rate Limits y Web Application Firewalls (WAF) realmente están funcionando.

**Comandos de ejemplo:**
```bash
# Simular "Credential Stuffing" masivo para ver si la cuenta se bloquea (Lockout) a los 5 fallos.
fractia attack --target https://api.example.com --profile bots-stuffing

# Ejecutar un ataque Slowloris para confirmar que tu Uvicorn dropea conexiones inactivas.
fractia attack --target https://api.example.com --profile slowloris
```

### Modo 2: Orquestador DAST (OWASP ZAP & Nuclei)
FractIA levanta motores estándar de la industria en segundo plano, les manda atacar tu URL y traduce sus reportados crudos a Markdown limpio.

**Comandos de ejemplo:**
```bash
# Mandar un Active Scan completo usando ZAP buscando Inyecciones SQL y XSS Reflejados en producción.
fractia attack --target https://api.example.com --profile zap-scan

# Usar Nuclei para fuzzear directorios ocultos (buscar `.git` expuestos, `.env` públicos).
fractia attack --target https://api.example.com --profile nuclei-fuzz
```

---

## ⚠️ Mejores Prácticas Generales

- **No expongas el puerto 7777 de FractIA a Internet**. Solo debe vivir en tu entorno de desarrollo local o mediante un túnel SSH cerrado.
- Cuando corras los **Módulos Activos (Pilar C)**, asegúrate de no hacer pruebas de estrés DoS en horarios pico de tus usuarios, la agresividad de estos scripts puede tirar contenedores pequeños.
