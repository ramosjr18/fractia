/**
 * logging.dart.js — Logging & Debug Leaks
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = { id: 'logging', name: 'Logging & Debug Leaks', severity: 'medium', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── CRITICAL: print() with sensitive data ────────────────────────────────
  const SENSITIVE_PRINT_RE = /print\s*\(\s*['"`]?.*(?:token|password|secret|auth|credential|key|email|user|login|error.*\$)/i;
  const printHits = grepFiles(dartFiles, SENSITIVE_PRINT_RE);
  for (const h of printHits) {
    findings.push({
      severity: 'high', title: 'print() con datos potencialmente sensibles',
      description: 'Los print() son visibles en logs de producción (adb logcat) y pueden exponer tokens, emails o errores con información interna.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Reemplaza por: if (kDebugMode) { debugPrint(\'descripción sin datos sensibles\'); }',
      cve: 'CWE-532: Insertion of Sensitive Information into Log File',
    });
  }

  // ── HIGH: Generic print() without kDebugMode guard ────────────────────────
  const allPrints = grepFiles(dartFiles, /\bprint\s*\(/);
  const guardedPrints = grepFiles(dartFiles, /kDebugMode.*print|print.*kDebugMode|if\s*\(\s*kDebugMode/i);
  const ungardedCount = allPrints.length - guardedPrints.length;
  if (ungardedCount > 5) {
    findings.push({
      severity: 'medium', title: `${ungardedCount} print() sin guardia kDebugMode`,
      description: 'Los print() sin kDebugMode se ejecutan en builds de producción y son visibles en adb logcat.',
      file: allPrints[0]?.file ? relPath(allPrints[0].file, projectRoot) : null,
      line: allPrints[0]?.lineNumber || null, code: allPrints[0]?.line || null,
      fix: 'Usa if (kDebugMode) { debugPrint(...); } o implementa un logger que sea no-op en release (el paquete logger).',
      cve: 'CWE-532',
    });
  }

  // ── MEDIUM: debugPrint() with sensitive data ──────────────────────────────
  const debugPrintHits = grepFiles(dartFiles, /debugPrint\s*\(.*(?:token|password|secret|error\s*\$)/i);
  for (const h of debugPrintHits) {
    findings.push({
      severity: 'medium', title: 'debugPrint() con datos sensibles',
      description: 'debugPrint() también es visible en logs de dispositivo aunque es menos grave que print().',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Evita loguear datos sensibles incluso en debug. Usa solo tipos de error, nunca el valor.',
      cve: 'CWE-532',
    });
  }

  // ── LOW: No structured logger package ────────────────────────────────────
  const hasLogger = pubspec?.hasDep('logger') || pubspec?.hasDep('fimber') || pubspec?.hasDep('logging');
  if (!hasLogger && allPrints.length > 0) {
    findings.push({
      severity: 'low', title: 'Sin paquete de logging estructurado',
      description: 'Usar print() directamente no permite controlar el nivel de log ni desactivarlos fácilmente en producción.',
      file: null, line: null, code: null,
      fix: 'Añade el paquete logger y configúralo con Level.nothing en producción.',
      cve: null,
    });
  }

  // ── MEDIUM: Stack traces exposed in error messages ────────────────────────
  const stackTraceHits = grepFiles(dartFiles, /catchError.*print|catch\s*\(.*\).*\{[^}]*print.*stackTrace/i);
  for (const h of stackTraceHits) {
    findings.push({
      severity: 'medium', title: 'Stack trace expuesto en logs',
      description: 'Imprimir stack traces en producción puede revelar rutas internas, nombres de paquetes y lógica del sistema.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'En producción, loguea solo el tipo de error. En debug puedes incluir el stack trace.',
      cve: 'CWE-209: Generation of Error Message Containing Sensitive Information',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de logging detectados` : 'Sin leaks en logs detectados' };
}
