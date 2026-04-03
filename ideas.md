# Fractia — Ideas & Roadmap

---

## Flutter/Dart Security Engine

### El problema

Fractia actualmente audita proyectos Node.js/Express (Code Engine) y servidores Linux (IronBase/Infra Engine). El proyecto **exampleapp** es una app Flutter/Dart que conecta al mismo backend que exampleapp-web, pero Fractia no puede auditarlo porque no lee ni analiza codigo Dart.

Flutter tiene su propio universo de vulnerabilidades: tokens en SharedPreferences sin cifrar, falta de certificate pinning, deep links sin validacion, ausencia de ofuscacion, y mas. Ninguna de las herramientas existentes (tipo Snyk o SonarQube) cubre bien Flutter desde una perspectiva de seguridad.

### Hallazgos reales en exampleapp (Flutter) que Fractia no puede detectar hoy

| Problema | Severidad | Detalle |
|----------|-----------|---------|
| Tokens en SharedPreferences (texto plano) | CRITICO | `sharedPreferences.setString('auth_token', accessToken)` — sin cifrado, visible en backups |
| Sin certificate pinning | ALTO | Usa `http` package basico — MITM trivial en redes comprometidas |
| Sin refresh token rotation | ALTO | No implementa refresh — logout forzoso al expirar |
| Sin `flutter_secure_storage` | ALTO | No esta ni en pubspec.yaml |
| Sin Android directory | ALTO | No hay AndroidManifest, Network Security Config, ni ProGuard |
| Sin ofuscacion de Dart | MEDIO | Codigo descompilable facilmente |
| print() con datos sensibles | MEDIO | `print('Error loading theme: $e')` — leaks en logs |
| Deep links sin auth validation | MEDIO | Cast inseguro: `settings.arguments as String?` |
| Sin validacion de input client-side | MEDIO | Solo backend valida |
| Sin session timeout | MEDIO | App no hace logout al ir a background |

### Arquitectura propuesta

```
fractia/
└── engines/
    ├── ironbase/             # Ya existe — Linux hardening (Bash)
    ├── ironbaseRunner.js     # Ya existe — wrapper Node.js
    ├── flutter/              # NUEVO — Dart/Flutter scanner
    │   ├── scanners/
    │   │   ├── auth.dart.js          # Auth & token storage
    │   │   ├── network.dart.js       # HTTP client, SSL pinning, MITM
    │   │   ├── storage.dart.js       # Secure storage vs SharedPreferences
    │   │   ├── deeplinks.dart.js     # Deep link validation & auth
    │   │   ├── crypto.dart.js        # Crypto patterns en Dart
    │   │   ├── platform.dart.js      # iOS/Android config (Info.plist, AndroidManifest)
    │   │   ├── deps.dart.js          # pubspec.yaml vulnerability check
    │   │   ├── obfuscation.dart.js   # Build config, ProGuard, R8
    │   │   ├── logging.dart.js       # print() leaks, debug flags
    │   │   └── state.dart.js         # State management security
    │   └── utils/
    │       ├── dartParser.js         # Lector de archivos .dart
    │       └── pubspecParser.js      # Parser de pubspec.yaml/lock
    └── flutterRunner.js      # NUEVO — orquestador (como ironbaseRunner.js)
```

### Los 10 modulos del Flutter Engine

#### 1. auth.dart.js — Autenticacion & Tokens
Que detecta:
- Tokens JWT almacenados en SharedPreferences (CRITICO — texto plano, accesible en backups)
- Falta de `flutter_secure_storage` en pubspec.yaml
- Tokens enviados como query params en URLs
- Ausencia de refresh token rotation
- Falta de check de expiracion de token al resumir la app
- Passwords no borrados de TextEditingControllers en dispose()
- Falta de biometric auth (local_auth) para operaciones sensibles
- Session timeout no implementado (app en background sin logout)

Patrones a buscar en exampleapp:
```dart
// VULNERABLE — exampleapp usa esto actualmente
await sharedPreferences.setString('auth_token', accessToken);
await sharedPreferences.setString('refresh_token', refreshToken);

// CORRECTO
await secureStorage.write(key: 'auth_token', value: accessToken);
```

#### 2. network.dart.js — HTTP Client & SSL Pinning
Que detecta:
- Uso de `http` package sin HttpClient personalizado (no soporta pinning)
- Ausencia de certificate pinning (MITM attack surface)
- APIs llamadas por HTTP en vez de HTTPS
- Falta de interceptors para retry y refresh token
- Timeouts no configurados o muy largos
- Ausencia de `dio` o `chopper` con interceptors de seguridad
- Requests sin manejo de errores de red

Patrones criticos:
```dart
// VULNERABLE — sin SSL pinning, sin interceptors
final response = await http.get(Uri.parse(url));

// RECOMENDADO — con Dio + certificate pinning
final dio = Dio();
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) {
    return cert.sha256 == expectedFingerprint;
  };
  return client;
};
```

#### 3. storage.dart.js — Almacenamiento Seguro
Que detecta:
- Datos sensibles en SharedPreferences (tokens, emails, datos personales)
- Falta de `flutter_secure_storage` en dependencias
- Falta de cifrado en cache local
- Datos de usuario almacenados sin proteccion
- Backups de Android que incluyen SharedPreferences (`android:allowBackup="true"`)

#### 4. deeplinks.dart.js — Deep Links & Navegacion
Que detecta:
- Rutas protegidas accesibles via deep link sin auth check
- Casts inseguros de argumentos de ruta (`settings.arguments as String?`)
- Falta de validacion de scheme/host en deep links
- Intent filters demasiado permisivos en AndroidManifest
- Universal Links sin verificacion de dominio en iOS
- Falta de `go_router` o `auto_route` con guards de auth

Patron vulnerable en exampleapp:
```dart
// VULNERABLE — cast sin validacion, no verifica auth
case AppConstants.projectDetailRoute:
  final projectId = settings.arguments as String?;
  return MaterialPageRoute(
    builder: (_) => ProjectDetailScreen(projectId: projectId ?? ''),
  );
```

#### 5. crypto.dart.js — Criptografia
Que detecta:
- Uso de `dart:math` Random() para tokens/IDs (predecible)
- Falta de `dart:crypto` o `pointycastle` para operaciones criptograficas
- IVs estaticos en cifrado AES
- MD5/SHA1 para datos sensibles
- Claves de cifrado hardcoded

#### 6. platform.dart.js — Configuracion iOS/Android
Que detecta:
- **iOS**: Info.plist sin configuracion ATS, falta de NSPrivacy keys, no Keychain usage
- **Android**: allowBackup=true, falta de Network Security Config, permisos excesivos, FLAG_SECURE no usado en pantallas sensibles
- Falta de `flutter_windowmanager` para evitar screenshots en pantallas con datos sensibles
- Debug mode detectado en builds de release

Ejemplo para exampleapp:
```xml
<!-- AndroidManifest.xml — VULNERABLE -->
<application android:allowBackup="true" ...>

<!-- CORRECTO -->
<application android:allowBackup="false"
             android:networkSecurityConfig="@xml/network_security_config" ...>
```

#### 7. deps.dart.js — Dependencias (pubspec)
Que detecta:
- Paquetes con CVEs conocidos (check contra advisories de pub.dev)
- Dependencias sin version pinned (ej: `^6.1.1` permite minor bumps)
- Paquetes abandonados (sin actualizacion en >1 ano)
- Dependencias de dev en produccion
- Falta de paquetes criticos de seguridad:
  - `flutter_secure_storage` (almacenamiento cifrado)
  - `local_auth` (biometria)
  - `certificate_pinning` o configuracion equivalente

Base de paquetes vulnerables conocidos:
```
http < 1.2.0         — No soporta custom HttpClient
shared_preferences    — NUNCA para tokens (plaintext)
path_provider < 2.0  — Path traversal en versiones antiguas
webview_flutter < 4.0 — XSS en versiones antiguas
url_launcher < 6.1    — Intent injection
```

#### 8. obfuscation.dart.js — Ofuscacion & Build Security
Que detecta:
- Falta de `--obfuscate --split-debug-info` en scripts de build
- ProGuard/R8 no configurado para Android
- Source maps incluidos en builds de release
- Assets sensibles (JSON con configuraciones, themes) incluidos sin cifrar
- Falta de code stripping en iOS

#### 9. logging.dart.js — Logging & Debug Leaks
Que detecta:
- `print()` statements con datos sensibles (tokens, emails, passwords)
- `debugPrint()` o `log()` con variables de usuario
- Falta de paquete de logging estructurado (`logger`, `fimber`)
- `kDebugMode` no usado para condicionar logs
- Error messages que exponen stack traces o rutas internas

Patron vulnerable en exampleapp:
```dart
// VULNERABLE — leaks del error al log
print('Error loading theme: $e');
print('Login failed: $error');

// CORRECTO
if (kDebugMode) print('Theme load error: ${e.runtimeType}');
```

#### 10. state.dart.js — State Management Security
Que detecta:
- Datos de usuario persistidos en estado global sin limpiar al logout
- Falta de limpieza de Provider/BLoC al cerrar sesion
- Tokens accesibles desde cualquier widget via Provider sin restriccion
- Estado de autenticacion no reactivo (app no reacciona a token expiry)

### Implementacion tecnica

**Lenguaje**: JavaScript (ES Modules), igual que los auditores de codigo. No necesitamos ejecutar Dart — todo es analisis estatico de texto.

**fileScanner.js ya soporta**:
- Lectura recursiva de archivos
- Grep con patrones regex
- Parseo de archivos de configuracion

**Lo que se necesita nuevo**:
1. `pubspecParser.js` — parsear `pubspec.yaml` y `pubspec.lock` (YAML simple, se puede hacer con regex o con un parser YAML ligero como `yaml` de npm)
2. `dartParser.js` — no necesita ser un AST completo. Grep + regex sobre archivos `.dart` funciona para el 90% de los checks
3. `flutterRunner.js` — orquestador identico al patron de `ironbaseRunner.js`, ejecuta scanners en paralelo

**Dependencia nueva**:
```bash
npm install yaml  # Para parsear pubspec.yaml (~2KB, sin subdependencias)
```

**Esfuerzo estimado**: 3-5 dias de trabajo concentrado para los 10 modulos + el runner + integracion en el dashboard.

### Dashboard integration

Anadir una tercera pestana al dashboard:

```
[Code Audit] [Infra Audit] [Mobile Audit]
```

El color del Mobile Audit seria naranja/amber (`#f59e0b`) para diferenciarlo del verde (code) y violeta (infra).

Nuevo endpoint:
```
POST /api/mobile-audit
body: { modules: ['auth', 'network', 'storage', ...], flutterRoot: '/path/to/flutter/project' }
```

Nueva variable `.env`:
```
FLUTTER_PROJECT_ROOT=/ruta/al/proyecto/flutter
```

### Prioridad de implementacion

| Prioridad | Modulo | Razon |
|-----------|--------|-------|
| P0 | auth.dart.js | Token storage es la vulnerabilidad #1 en apps Flutter |
| P0 | network.dart.js | SSL pinning ausente = MITM trivial |
| P0 | storage.dart.js | SharedPreferences = texto plano |
| P1 | platform.dart.js | allowBackup, ATS, permisos |
| P1 | deps.dart.js | Paquetes vulnerables |
| P1 | deeplinks.dart.js | Acceso no autorizado via deep links |
| P2 | obfuscation.dart.js | Reverse engineering |
| P2 | logging.dart.js | Info leaks en logs |
| P2 | crypto.dart.js | Patrones criptograficos debiles |
| P3 | state.dart.js | State management post-logout |

## Módulos de OpSec & Anonimato (IMPLEMENTADO V3.0)

Se ha integrado un motor de anonimato profesional para auditorías DAST, permitiendo ruteo anónimo y evasión de bloqueos.

### Características
- **Tor Stealth Bridge**: Proxy SOCKS5 local (9050) auto-gestionado.
- **Rotación de Identidad**: Comando `tor --rotate` para obtener nueva IP de salida al instante.
- **OS/TTL Fingerprinting**: Spoofing de TTL (64 vs 128) para ocultar el OS real.
- **User-Agent Spoofing**: Rotación de cabeceras de navegador reales.
- **Sandbox Integrado**: Laboratorio Docker con targets vulnerables y herramientas de ataque pre-configuradas.

### Comandos CLI
```bash
fractia sandbox [up|down|shell|status|build]
fractia tor [--start|--stop|--rotate|--status]
```

---

## Otras ideas futuras

### Auditor de React/Vue generico (frontend.js)
Un modulo para SPAs que no son Next.js — React puro, Vue, Svelte. Detectaria:
- XSS via innerHTML, v-html, {@html}
- Tokens en localStorage
- CORS en fetch/axios client-side
- Dependencias frontend con CVEs

### Modo CI/CD
Ejecutar Fractia como parte de un pipeline de CI:
```bash
fractia scan --engine code --depth standard --format json --exit-code
```
Retorna exit code 1 si hay vulnerabilidades criticas. Compatible con GitHub Actions, GitLab CI, etc.

### Motor de Python (Django/Flask/FastAPI)
Analogo al Code Engine pero para backends Python:
- SQL injection en queries raw
- CSRF configuration
- SECRET_KEY hardcoded
- Debug mode en produccion
- pip audit para dependencias

### Report PDF
Generar un PDF profesional con el reporte completo para entregar a clientes o stakeholders. Usar la skill de PDF de Fractia para esto.

---

## VPN & Anonymity Engine (OpSec)

#### 1. El camino de Tor (The Onion Router) — "Extremo y Gratis"
Podemos integrar un módulo en Fractia que use la red Tor.
- **Dificultad**: Media. Ya tenemos la lógica de proxies en `utils/opsec.js`. Solo hay que instalar el servicio `tor` localmente y configurar Fractia para que rutee todo a través del puerto 9050.
- **Costo**: $0.
- **Anonimato**: El más alto posible. Nadie sabe quién eres (ni siquiera el nodo de salida).

#### 2. VPN Gate (Proyecto Académico SoftEther) — "Voluntariado"
Existe un proyecto de la Universidad de Tsukuba donde miles de voluntarios ofrecen sus servidores como nodos VPN gratuitos.
- **Dificultad**: Media-Alta. Podemos codear un **Scraper** en Fractia que descargue la lista pública de servidores de VPN Gate diariamente, elija uno al azar y conecte mediante OpenVPN.
- **Costo**: $0.
- **Anonimato**: Bueno, pero dependes de la buena fe del voluntario que hostea el nodo (podría guardar logs).

#### 3. Oracle Cloud / GCP Free Tier — "IP Estática Gratis"
Si tienes una cuenta de Oracle Cloud (por ejemplo), te dan 2 servidores gratis para siempre.
- **Dificultad**: Baja. Simplemente codeamos el script de instalación de WireGuard para tu servidor gratuito y Fractia lo usa como nodo fijo.
- **Costo**: $0 (pero requiere tarjeta para verificar identidad en el registro).

---

### [IMPLEMENTANDO] Tor Stealth Bridge
Propuesta para anonimato gratuito, abierto y "hecho en casa":
1. **Instalación Silenciosa**: Detectar o instalar `tor` en el host o sandbox.
2. **SOCKS5 Wrapper**: Codear un túnel que envuelva todos los ataques de Fractia (nmap, nuclei, zap, etc).
3. **Rotación Automática**: Cambiar la identidad de Tor (IP de salida) cada X minutos o bajo demanda.
