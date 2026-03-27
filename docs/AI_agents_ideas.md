# FractIA: Integración y Futuro con Inteligencia Artificial 🧠

FractIA utiliza Inteligencia Artificial (LLMs avanzados como Claude 3.5 Sonnet y GPT-4o) para dotar de razonamiento humano al análisis estático (SAST), filtrando el ruido tradicional de los escáneres de seguridad.

---

## 🔬 Estado Actual: ¿Cómo usa FractIA la IA y cómo funciona?

Actualmente, FractIA implementa dos modos principales que integran IA dentro del **Code Engine** (Pilar A):

### 1. El Modo "Deep Audit" (Eliminador de Falsos Positivos)
Normalmente, si un escáner ve la palabra `eval(` o `query(` en tu código, levanta una alerta roja.
FractIA toma ese hallazgo sospechoso, ofusca los secretos mediante expresiones regulares para no enviar datos privados a la nube, y le envía un pequeño bloque de contexto (`snippet`) al LLM.

**Lo que hace la IA:**
- Analiza el contexto sintáctico: ¿Ese `query()` recibe datos sanitizados, o concatena directamente datos del usuario (`req.body`)?
- Si la IA concluye que el código está protegido (por un middleware o validación previa), **descarta** el hallazgo.
- Si confirma la vulnerabilidad, explica detalladamente por qué es explotable en lenguaje humano.

### 2. El Modo "Full Pentest" (Constructor de Vectores)
Es una evolución del Deep Audit. No solo confirma que hay una brecha, sino que utiliza a la IA para comportarse de forma perversa.

**Lo que hace la IA:**
- Genera un payload real de ataque (ej. un comando Curl con SQLi estructurado) que demuestra exactamente cómo un criminal explotaría esa línea de código en particular.
- Describe la cadena de ataque (ej. Paso 1: Evadir el JWT; Paso 2: Inyectar SQL; Paso 3: Pivotar).

---

## 🚀 El Futuro: Ideas para "AI Agents" de Verdadera Utilidad en Seguridad

Hasta ahora, usamos la IA como un "Juez" estático o "Consultor". Para llevarlo al siguiente nivel, debemos usar **Agentes (IA Activa)**. Un Agente puede razonar, usar herramientas (ejecutar comandos, navegar) y tomar decisiones autónomas.

Aquí hay ideas para implementar Agentes de Seguridad con alto impacto técnico:

### 1. El Hacker Autónomo (Agentic DAST)
Conectaríamos la IA al Pilar C (Pentesting DAST) que ideamos antes.
- **Funcionamiento**: En lugar de configurar un ataque fijo en ZAP que solo tira payloads a ciegas, el Agente lee la respuesta HTTP del servidor objetivo.
- **Utilidad Real**: Si el servidor responde `403 Forbidden - WAF Blocked`, el Agente razona: *"Me bloquearon porque detectaron las comillas del SQL. Voy a codificar el payload en Base64 o usar Hex-encoding e intentar de nuevo"*. Aprende de las defensas y las esquiva en tiempo real como un humano.

### 2. Auto-Remediation Agent (El Fixer)
¿Por qué solo decirle al desarrollador que tiene una vulnerabilidad de XSS, si el Agente puede arreglarla solo?
- **Funcionamiento**: Cuando el escáner detecta un fallo, el Agente hace checkout a una nueva rama del repositorio (ej. `sec-fix-xss-login`), abre tu archivo Node.js o Python, importa la librería correcta, cambia tu código para mitigar el ataque, **corre las pruebas unitarias locales para asegurarse de no romper la app**, y te abre una Pull Request terminada.
- **Utilidad Real**: Cero horas perdidas por tu equipo de Devs parcheando librerías. Solo revisar PRs escritas por la IA.

### 3. Agente de "Threat Intelligence" Sensorial (Blue Team)
Un Agente que nunca se apaga y se alimenta constantemente de tu entorno en Producción.
- **Funcionamiento**: El Agente se conecta a tus logs de Docker o del backend de Node.js de producción por Streaming. No busca errores convencionales (500s), sino "Comportamiento Anómalo Analítico".
- **Utilidad Real**: Si detecta que una IP legítima empezó a consultar usuarios en orden alfabético cada 5 minutos de forma despaciosa (indetectable para un Rate Limiter bruto), el Agente se da cuenta de que es un *Bot Scraper* sutil. Inmediatamente el Agente ejecuta un bloqueo de IP temporal contactando a tu Firewall o a Coolify a través de su API.

### 4. Reviewer Arquitectural Continuo (Shift-Left)
- **Funcionamiento**: Un agente que se integra como un Webhook en tus revisiones de GitHub.
- **Utilidad Real**: Actúa igual que la persona de seguridad (Security Champion) del equipo. Antes de que tú o tus devs pulleen algo a la rama `main`, el agente audita la lógica de la PR. Si metieron una librería nueva (`npm install nueva-lib`), el Agente busca CVEs vivos ayer en internet de esa librería. Si no es segura, bloquea el Merge automáticamente dictando por qué en los comentarios de GitHub.
