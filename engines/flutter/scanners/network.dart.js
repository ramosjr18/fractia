/**
 * network.dart.js — HTTP Client & SSL Pinning
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = { id: 'network', name: 'Network & SSL Pinning', severity: 'high', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── CRITICAL: No SSL pinning ──────────────────────────────────────────────
  const hasPinning = pubspec?.hasDep('ssl_pinning_plugin')
    || pubspec?.hasDep('dio_pinning')
    || grepFiles(dartFiles, /badCertificateCallback|sha256|fingerprint.*cert|SecurityContext|withTrustedRoots/i).length > 0;

  if (!hasPinning) {
    findings.push({
      severity:    'high',
      title:       'Sin certificate pinning (MITM trivial)',
      description: 'La app acepta cualquier certificado TLS válido. En redes comprometidas (WiFi público, VPN maliciosa) un atacante puede interceptar todo el tráfico con un proxy.',
      file:        null, line: null, code: null,
      fix:         'Configura Dio con un HttpClient personalizado que valide el fingerprint SHA256 del certificado del servidor.',
      cve:         'CWE-295: Improper Certificate Validation',
    });
  }

  // ── HIGH: Plain HTTP calls ────────────────────────────────────────────────
  const httpCalls = grepFiles(dartFiles, /Uri\.parse\s*\(\s*['"]http:\/\//i);
  for (const h of httpCalls) {
    findings.push({
      severity:    'high',
      title:       'Llamada HTTP sin cifrado',
      description: 'URL con http:// — el tráfico viaja en texto plano, interceptable en cualquier red.',
      file:        relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix:         'Cambia http:// por https:// y verifica que el servidor tenga TLS activo.',
      cve:         'CWE-319: Cleartext Transmission',
    });
  }

  // ── HIGH: http package without custom client (no pinning possible) ─────────
  const usesBasicHttp = grepFiles(dartFiles, /import\s+['"]package:http\/http\.dart['"]/);
  const hasCustomClient = grepFiles(dartFiles, /HttpClient\s*\(\s*\)|IOClient|BaseClient/i).length > 0;
  if (usesBasicHttp.length > 0 && !hasCustomClient) {
    findings.push({
      severity:    'medium',
      title:       'Paquete http sin HttpClient personalizado',
      description: 'El paquete http básico no permite configurar SSL pinning sin un HttpClient personalizado.',
      file:        relPath(usesBasicHttp[0].file, projectRoot),
      line:        usesBasicHttp[0].lineNumber, code: usesBasicHttp[0].line,
      fix:         'Migra a Dio con IOHttpClientAdapter para poder configurar certificado pinning y interceptors.',
      cve:         'CWE-295',
    });
  }

  // ── MEDIUM: No retry / refresh token interceptor ─────────────────────────
  const hasInterceptor = grepFiles(dartFiles, /Interceptor|InterceptorsWrapper|onRequest|onResponse|onError.*dio/i).length > 0;
  if (!hasInterceptor && pubspec?.hasDep('dio')) {
    findings.push({
      severity:    'medium',
      title:       'Dio sin interceptors de seguridad',
      description: 'Se usa Dio pero sin interceptors. No hay manejo automático de refresh token en 401 ni logging seguro de errores.',
      file:        null, line: null, code: null,
      fix:         'Añade un InterceptorsWrapper que capture 401 y ejecute el refresh token automáticamente.',
      cve:         'CWE-613',
    });
  }

  // ── MEDIUM: No timeout configured ────────────────────────────────────────
  const hasTimeout = grepFiles(dartFiles, /connectTimeout|receiveTimeout|sendTimeout|timeout.*Duration/i).length > 0;
  if (!hasTimeout) {
    findings.push({
      severity:    'low',
      title:       'Sin timeouts configurados en requests HTTP',
      description: 'Sin timeouts, la app puede quedar colgada indefinidamente esperando una respuesta del servidor.',
      file:        null, line: null, code: null,
      fix:         'Configura BaseOptions con connectTimeout: Duration(seconds: 10), receiveTimeout: Duration(seconds: 15).',
      cve:         'CWE-400: Uncontrolled Resource Consumption',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de red detectados` : 'Configuración de red sin vulnerabilidades críticas' };
}
