/**
 * state.dart.js — State Management Security
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = { id: 'state', name: 'State Management Security', severity: 'medium', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── HIGH: User state not cleared on logout ────────────────────────────────
  const hasLogout = grepFiles(dartFiles, /logout|signOut|logOut/i).length > 0;
  const hasClearState = grepFiles(dartFiles, /\.clear\s*\(\s*\)|notifyListeners.*null|emit\s*\(.*null\)|reset\s*\(\s*\)|\.state\s*=\s*null/i).length > 0;
  if (hasLogout && !hasClearState) {
    findings.push({
      severity: 'high', title: 'Estado de usuario no limpiado al hacer logout',
      description: 'Se detectó logout pero sin limpiar el estado del Provider/BLoC/Riverpod. Datos del usuario pueden persistir en memoria y ser accesibles.',
      file: null, line: null, code: null,
      fix: 'Al hacer logout, llama a notifyListeners() con todos los campos a null, o emite un estado vacío en el BLoC/Cubit.',
      cve: 'CWE-459: Incomplete Cleanup',
    });
  }

  // ── HIGH: Global state accessible without restriction ─────────────────────
  const globalProviders = grepFiles(dartFiles, /Provider\.of\s*<.*>\s*\(.*listen.*:\s*false\)|context\.read\s*<.*>\s*\(\s*\)/i);
  const authRelatedGlobal = globalProviders.filter(h => /auth|user|token|session/i.test(h.line));
  if (authRelatedGlobal.length > 3) {
    findings.push({
      severity: 'medium', title: 'Estado de autenticación accesible desde múltiples widgets',
      description: `Se accede al estado de auth desde ${authRelatedGlobal.length} lugares. Centraliza el acceso a datos sensibles.`,
      file: null, line: null, code: null,
      fix: 'Usa un único repositorio de autenticación y expón solo lo necesario (isLoggedIn) en lugar del objeto de usuario completo.',
      cve: 'CWE-668: Exposure of Resource to Wrong Sphere',
    });
  }

  // ── MEDIUM: Auth state not reactive (no stream/listen for token expiry) ────
  const hasAuthStream = grepFiles(dartFiles, /authStateChanges|userStream|onAuthStateChanged|TokenExpired|tokenExpiry/i).length > 0;
  if (!hasAuthStream && hasLogout) {
    findings.push({
      severity: 'medium', title: 'Estado de autenticación no reactivo',
      description: 'No se detectó un stream que reaccione a la expiración del token. Si el token expira en background, la app no fuerza re-autenticación.',
      file: null, line: null, code: null,
      fix: 'Implementa un StreamController o usa un timer que verifique la expiración del JWT y emita un evento de logout.',
      cve: 'CWE-613: Insufficient Session Expiration',
    });
  }

  // ── MEDIUM: Sensitive data in global state ────────────────────────────────
  const sensitiveStatePatterns = [
    /class.*State.*\{[^}]*(?:password|token|secret|cardNumber)/i,
    /(?:String|dynamic)\s+(?:password|token|secret)\s*[=;]/i,
  ];
  for (const pattern of sensitiveStatePatterns) {
    const hits = grepFiles(dartFiles, pattern);
    for (const h of hits) {
      if (!h.line.includes('//')) {
        findings.push({
          severity: 'medium', title: 'Dato sensible en clase de estado',
          description: 'Datos sensibles en clases de estado pueden ser serializados, logueados o accedidos desde cualquier widget.',
          file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
          fix: 'No almacenes tokens o passwords en el estado global. Accede directamente desde SecureStorage cuando los necesites.',
          cve: 'CWE-312',
        });
      }
    }
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de state management` : 'State management sin vulnerabilidades detectadas' };
}
