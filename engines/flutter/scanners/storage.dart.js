/**
 * storage.dart.js — Almacenamiento Seguro
 */
import { grepFiles, relPath } from '../utils/dartParser.js';
import { readFileSync } from 'fs';
import path from 'path';

export const meta = { id: 'storage', name: 'Secure Storage', severity: 'critical', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── CRITICAL: Sensitive data in SharedPreferences ─────────────────────────
  const SENSITIVE_PATTERNS = [
    { re: /(?:prefs|sharedPreferences|_prefs)\.set(?:String|Int|Bool)\s*\(\s*['"][^'"]*(?:token|password|secret|key|auth|credential|pin|card)[^'"]*['"]/i, label: 'dato sensible' },
    { re: /SharedPreferences\.getInstance\s*\(\s*\)/i, label: 'uso de SharedPreferences (revisar qué se almacena)' },
  ];

  for (const { re, label } of SENSITIVE_PATTERNS) {
    const hits = grepFiles(dartFiles, re);
    for (const h of hits) {
      findings.push({
        severity:    'critical',
        title:       `SharedPreferences almacena ${label}`,
        description: 'SharedPreferences guarda datos en XML/JSON sin cifrado. Cualquier app con acceso root o un backup ADB puede leerlos.',
        file:        relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
        fix:         'Reemplaza por flutter_secure_storage que usa Android Keystore / iOS Keychain.',
        cve:         'CWE-312: Cleartext Storage of Sensitive Information',
      });
    }
  }

  // ── HIGH: flutter_secure_storage absent ──────────────────────────────────
  if (pubspec && !pubspec.hasDep('flutter_secure_storage')) {
    findings.push({
      severity: 'high', title: 'flutter_secure_storage no instalado',
      description: 'Sin este paquete la app no puede almacenar nada de forma segura en el dispositivo.',
      file: 'pubspec.yaml', line: null, code: null,
      fix: 'flutter_secure_storage: ^9.0.0 en pubspec.yaml',
      cve: 'CWE-312',
    });
  }

  // ── HIGH: Android allowBackup ─────────────────────────────────────────────
  const manifestPath = path.join(projectRoot, 'android', 'app', 'src', 'main', 'AndroidManifest.xml');
  let manifest = '';
  try { manifest = readFileSync(manifestPath, 'utf8'); } catch {}
  if (manifest && /android:allowBackup\s*=\s*["']true["']/i.test(manifest)) {
    findings.push({
      severity: 'high', title: 'android:allowBackup="true" en AndroidManifest',
      description: 'Con allowBackup=true cualquier usuario puede extraer los datos de la app (incluido SharedPreferences) vía adb backup sin root.',
      file: 'android/app/src/main/AndroidManifest.xml', line: null, code: null,
      fix: 'Cambia a android:allowBackup="false" o configura un fullBackupContent que excluya datos sensibles.',
      cve: 'CWE-530: Exposure of Backup File to Unauthorized Control Sphere',
    });
  }

  // ── MEDIUM: Unencrypted local cache ──────────────────────────────────────
  const cacheHits = grepFiles(dartFiles, /File\s*\(.*\.json\s*\).*writeAsString|jsonEncode.*write|cache.*write/i);
  for (const h of cacheHits) {
    findings.push({
      severity: 'medium', title: 'Cache local potencialmente sin cifrar',
      description: 'Se detectó escritura de datos en archivos locales. Si contienen datos de usuario, deberían estar cifrados.',
      file: relPath(h.file, projectRoot), line: h.lineNumber, code: h.line,
      fix: 'Usa encrypt + flutter_secure_storage para cifrar datos antes de escribirlos al disco.',
      cve: 'CWE-312',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de almacenamiento detectados` : 'Almacenamiento seguro correcto' };
}
