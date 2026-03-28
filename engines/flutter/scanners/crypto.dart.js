/**
 * crypto.dart.js — Patrones criptográficos débiles
 */
import { grepFiles, relPath } from '../utils/dartParser.js';

export const meta = { id: 'crypto', name: 'Cryptography', severity: 'high', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── CRITICAL: dart:math Random() for security (not Random.secure()) ────────
  const insecureRandom = grepFiles(dartFiles, /Random\s*\(\s*\)(?!\.secure)/);
  for (const h of insecureRandom) {
    // Only flag if used near token/key/id generation
    if (/token|key|id|secret|nonce|salt|iv|password/i.test(h.line)) {
      findings.push({
        severity: 'critical', title: 'Random() predecible para datos de seguridad',
        description: 'dart:math Random() no es criptográficamente seguro. Los tokens generados con él son predecibles.',
        file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
        fix: 'Usa Random.secure() de dart:math o la API de dart:crypto para generación de tokens seguros.',
        cve: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator',
      });
    }
  }

  // ── HIGH: MD5 or SHA1 for sensitive data ──────────────────────────────────
  const weakHash = grepFiles(dartFiles, /md5\.convert|sha1\.convert|MD5\.|\.sha1\(|hashMd5|hashSha1/i);
  for (const h of weakHash) {
    findings.push({
      severity: 'high', title: 'Hash débil MD5/SHA1 detectado',
      description: 'MD5 y SHA1 están rotos criptográficamente. No deben usarse para passwords, tokens o firmas.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Usa SHA-256 o superior: crypto.sha256.convert(utf8.encode(data))',
      cve: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    });
  }

  // ── HIGH: Hardcoded encryption keys ──────────────────────────────────────
  const hardcodedKeys = grepFiles(dartFiles, /(?:key|secret|iv|salt)\s*=\s*['"][A-Za-z0-9+/=]{16,}['"]/i);
  for (const h of hardcodedKeys) {
    findings.push({
      severity: 'high', title: 'Clave de cifrado hardcodeada',
      description: 'Claves de cifrado en el código fuente son visibles tras descompilar el APK.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Obtén las claves desde flutter_secure_storage, el Keystore del sistema, o un KMS externo. Nunca en código.',
      cve: 'CWE-321: Use of Hard-coded Cryptographic Key',
    });
  }

  // ── HIGH: Static IV in AES ────────────────────────────────────────────────
  const staticIV = grepFiles(dartFiles, /IV\s*=\s*IV\.fromLength\s*\(\s*16\s*\)|iv\s*=\s*\[0[\s,0]+\]/i);
  for (const h of staticIV) {
    findings.push({
      severity: 'high', title: 'IV estático en cifrado AES',
      description: 'Un IV estático hace que el mismo texto plano siempre produzca el mismo cifrado, rompiendo la confidencialidad.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Genera un IV aleatorio por operación: IV.fromSecureRandom(16)',
      cve: 'CWE-329: Not Using an Unpredictable IV with CBC Mode',
    });
  }

  // ── MEDIUM: ECB mode ─────────────────────────────────────────────────────
  const ecbMode = grepFiles(dartFiles, /AES\.mode\.ecb|SalsaMode\.ecb|BlockCipher.*ECB/i);
  for (const h of ecbMode) {
    findings.push({
      severity: 'medium', title: 'Cifrado en modo ECB (inseguro)',
      description: 'El modo ECB no oculta patrones en el texto plano. Usa CBC con IV aleatorio o GCM.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Usa AES.mode.cbc con IV.fromSecureRandom(16) o preferiblemente AES-GCM para autenticación.',
      cve: 'CWE-327',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} vulnerabilidad(es) criptográfica(s)` : 'Sin patrones criptográficos débiles' };
}
