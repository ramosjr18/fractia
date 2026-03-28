/**
 * auth.dart.js — Autenticación & Tokens
 * Detecta: tokens en SharedPreferences, falta de secure storage,
 * ausencia de session timeout, passwords no limpiados, etc.
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = {
  id:       'auth',
  name:     'Auth & Token Storage',
  severity: 'critical',
  pilar:    'Mobile',
};

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── CRITICAL: Tokens in SharedPreferences ─────────────────────────────────
  const SENSITIVE_KEYS = [
    /sharedPreferences\.setString\s*\(\s*['"][^'"]*(?:token|auth|jwt|access|refresh|secret|password|credential)[^'"]*['"]/i,
    /prefs\.setString\s*\(\s*['"][^'"]*(?:token|auth|jwt|access|refresh|secret|password|credential)[^'"]*['"]/i,
    /SharedPreferences.*setString.*token/i,
  ];

  for (const pattern of SENSITIVE_KEYS) {
    const hits = grepFiles(dartFiles, pattern);
    for (const h of hits) {
      findings.push({
        severity:    'critical',
        title:       'Token almacenado en SharedPreferences (texto plano)',
        description: 'SharedPreferences no está cifrado. Los tokens son accesibles en backups de Android y por otras apps en dispositivos rooteados.',
        file:        relPath(h.file, projectRoot),
        line:        h.lineNumber,
        code:        h.line,
        fix:         'Usa flutter_secure_storage: await secureStorage.write(key: \'auth_token\', value: token);',
        cve:         'CWE-312: Cleartext Storage of Sensitive Information',
      });
    }
  }

  // ── HIGH: No flutter_secure_storage in pubspec ─────────────────────────────
  if (pubspec && !pubspec.hasDep('flutter_secure_storage')) {
    findings.push({
      severity:    'high',
      title:       'flutter_secure_storage no instalado',
      description: 'La app no usa almacenamiento cifrado. Los datos sensibles pueden estar en texto plano.',
      file:        'pubspec.yaml',
      line:        null,
      code:        null,
      fix:         'Añade a pubspec.yaml: flutter_secure_storage: ^9.0.0',
      cve:         'CWE-312',
    });
  }

  // ── HIGH: No refresh token rotation / handling ─────────────────────────────
  const hasRefreshLogic = grepFiles(dartFiles, /refresh.?token|refreshToken|token.*refresh/i).length > 0;
  if (!hasRefreshLogic) {
    findings.push({
      severity:    'high',
      title:       'Sin refresh token rotation',
      description: 'No se detectó manejo de refresh tokens. Al expirar el access token, el usuario queda deslogueado sin poder renovar la sesión silenciosamente.',
      file:        null,
      line:        null,
      code:        null,
      fix:         'Implementa un interceptor Dio que detecte 401 y ejecute automáticamente el refresh del token antes de reintentar la petición.',
      cve:         'CWE-613: Insufficient Session Expiration',
    });
  }

  // ── MEDIUM: Passwords not cleared in dispose() ────────────────────────────
  const controllerHits = grepFiles(dartFiles, /TextEditingController\s*\(\s*\)/);
  const disposeHits    = grepFiles(dartFiles, /\.dispose\s*\(\s*\)/);
  if (controllerHits.length > 0 && disposeHits.length === 0) {
    findings.push({
      severity:    'medium',
      title:       'TextEditingControllers sin dispose()',
      description: 'Los controllers de campos de contraseña pueden retener datos en memoria si no se liberan correctamente.',
      file:        controllerHits[0]?.file ? relPath(controllerHits[0].file, projectRoot) : null,
      line:        controllerHits[0]?.lineNumber || null,
      code:        controllerHits[0]?.line || null,
      fix:         'Llama a _passwordController.dispose() en el método dispose() del State.',
      cve:         'CWE-316: Cleartext Storage in Memory',
    });
  }

  // ── MEDIUM: No session timeout ────────────────────────────────────────────
  const hasSessionTimeout = grepFiles(dartFiles, /AppLifecycleState\.paused|WidgetsBindingObserver|didChangeAppLifecycleState/i).length > 0;
  if (!hasSessionTimeout) {
    findings.push({
      severity:    'medium',
      title:       'Sin session timeout al ir a background',
      description: 'La app no detecta cuando va a background para lanzar logout o re-autenticación biométrica. Un atacante con acceso físico al dispositivo puede retomar la sesión.',
      file:        null,
      line:        null,
      code:        null,
      fix:         'Implementa WidgetsBindingObserver y en didChangeAppLifecycleState(AppLifecycleState.paused) inicia un timer de sesión.',
      cve:         'CWE-613',
    });
  }

  // ── LOW: No biometric auth for sensitive ops ──────────────────────────────
  const hasBiometric = pubspec?.hasDep('local_auth') || grepFiles(dartFiles, /local_auth|LocalAuthentication|authenticateWithBiometrics/i).length > 0;
  if (!hasBiometric) {
    findings.push({
      severity:    'low',
      title:       'Sin autenticación biométrica',
      description: 'No se detectó uso de local_auth para proteger operaciones sensibles (pagos, datos privados).',
      file:        null,
      line:        null,
      code:        null,
      fix:         'Añade local_auth: ^2.1.0 y usa authenticate() antes de acciones críticas.',
      cve:         'CWE-287: Improper Authentication',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const maxSev = findings.reduce((best, f) => {
    const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
    return rank[f.severity] > rank[best] ? f.severity : best;
  }, 'ok');

  return {
    module:   meta.id,
    name:     meta.name,
    severity: findings.length ? maxSev : 'ok',
    findings,
    passed:   findings.length === 0,
    summary:  findings.length
      ? `${findings.length} problema(s) detectado(s) en auth & tokens`
      : 'Sin vulnerabilidades de autenticación detectadas',
  };
}
