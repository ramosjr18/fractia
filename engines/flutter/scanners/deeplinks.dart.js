/**
 * deeplinks.dart.js — Deep Links & Navegación
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = { id: 'deeplinks', name: 'Deep Links & Navigation', severity: 'high', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── HIGH: Unsafe cast of route arguments ─────────────────────────────────
  const unsafeCasts = grepFiles(dartFiles, /settings\.arguments\s+as\s+\w+/i);
  for (const h of unsafeCasts) {
    findings.push({
      severity: 'high', title: 'Cast inseguro de argumentos de ruta',
      description: 'settings.arguments as Type lanza una excepción si se pasa un tipo incorrecto. Un deep link malicioso puede crashear la app o eludir validaciones.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Usa settings.arguments is Type ? settings.arguments as Type : defaultValue, o valida antes del cast.',
      cve: 'CWE-20: Improper Input Validation',
    });
  }

  // ── HIGH: Routes accessible without auth check ────────────────────────────
  const routeBuilders = grepFiles(dartFiles, /MaterialPageRoute\s*\(\s*builder/i);
  const authChecks    = grepFiles(dartFiles, /isAuthenticated|isLoggedIn|authState|AuthGuard|requiresAuth/i);
  if (routeBuilders.length > 3 && authChecks.length === 0) {
    findings.push({
      severity: 'high', title: 'Rutas sin guards de autenticación',
      description: 'Se detectaron múltiples rutas pero sin ningún guard de autenticación. Un deep link podría dar acceso directo a pantallas privadas.',
      file: null, line: null, code: null,
      fix: 'Implementa un route guard (con go_router o auto_route) que verifique el estado de auth antes de cada navegación.',
      cve: 'CWE-285: Improper Authorization',
    });
  }

  // ── MEDIUM: No go_router or auto_route ────────────────────────────────────
  const hasSecureRouter = pubspec?.hasDep('go_router') || pubspec?.hasDep('auto_route');
  if (!hasSecureRouter && routeBuilders.length > 2) {
    findings.push({
      severity: 'medium', title: 'Sin router con guards (go_router / auto_route)',
      description: 'El routing manual con Navigator no tiene mecanismos nativos de auth guards. Es fácil introducir rutas accesibles sin autenticación.',
      file: null, line: null, code: null,
      fix: 'Migra a go_router con redirect para verificar autenticación en cada ruta.',
      cve: 'CWE-284: Improper Access Control',
    });
  }

  // ── MEDIUM: No validation of deep link scheme/host ────────────────────────
  const deepLinkHandlers = grepFiles(dartFiles, /getInitialUri|getUriLinksStream|onLink|intentDataStreamListener/i);
  const hasSchemeValidation = grepFiles(dartFiles, /uri\.scheme.*==|uri\.host.*==|allowedSchemes|allowedHosts/i).length > 0;
  if (deepLinkHandlers.length > 0 && !hasSchemeValidation) {
    findings.push({
      severity: 'medium', title: 'Deep links sin validación de scheme/host',
      description: 'Se procesan deep links sin validar el scheme y host. Un atacante puede construir links maliciosos que la app procesará.',
      file: deepLinkHandlers[0]?.file ? relPath(deepLinkHandlers[0].file, projectRoot) : null,
      line: deepLinkHandlers[0]?.lineNumber || null, code: deepLinkHandlers[0]?.line || null,
      fix: 'Valida que uri.scheme == "tuapp" && uri.host == "tu-dominio.com" antes de procesar cualquier deep link.',
      cve: 'CWE-601: URL Redirection to Untrusted Site',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) en deep links/navegación` : 'Navegación sin vulnerabilidades detectadas' };
}
