/**
 * platform.dart.js — Configuración iOS/Android (manifests, plist, permisos)
 */
import { readFileSync } from 'fs';
import path from 'path';

export const meta = { id: 'platform', name: 'Platform Config (Android/iOS)', severity: 'high', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── ANDROID ───────────────────────────────────────────────────────────────
  const manifestPath = path.join(projectRoot, 'android', 'app', 'src', 'main', 'AndroidManifest.xml');
  let manifest = '';
  try { manifest = readFileSync(manifestPath, 'utf8'); } catch {}

  if (manifest) {
    // allowBackup
    if (/android:allowBackup\s*=\s*["']true["']/i.test(manifest)) {
      findings.push({
        severity: 'high', title: 'android:allowBackup="true"',
        description: 'Permite extraer datos de la app via adb backup sin root, incluyendo SharedPreferences y bases de datos.',
        file: 'android/app/src/main/AndroidManifest.xml', line: null, code: null,
        fix: 'Cambia a android:allowBackup="false"',
        cve: 'CWE-530',
      });
    }

    // Network Security Config
    if (!/android:networkSecurityConfig/i.test(manifest)) {
      findings.push({
        severity: 'medium', title: 'Sin Network Security Config en Android',
        description: 'Sin network_security_config.xml la app puede conectarse a dominios HTTP o aceptar certificados de usuario sin restricciones.',
        file: 'android/app/src/main/AndroidManifest.xml', line: null, code: null,
        fix: 'Añade android:networkSecurityConfig="@xml/network_security_config" y crea res/xml/network_security_config.xml con cleartextTrafficPermitted="false".',
        cve: 'CWE-319',
      });
    }

    // Excessive permissions
    const dangerousPerms = [
      'android.permission.READ_CONTACTS',
      'android.permission.READ_SMS',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.RECORD_AUDIO',
      'android.permission.READ_CALL_LOG',
    ];
    for (const perm of dangerousPerms) {
      if (manifest.includes(perm)) {
        findings.push({
          severity: 'low', title: `Permiso sensible: ${perm.split('.').pop()}`,
          description: `La app solicita ${perm}. Si no es estrictamente necesario, retíralo.`,
          file: 'android/app/src/main/AndroidManifest.xml', line: null, code: null,
          fix: `Elimina el permiso si no se usa. Si se usa, documenta la justificación en la ficha del Play Store.`,
          cve: 'CWE-250: Execution with Unnecessary Privileges',
        });
      }
    }

    // debuggable in release
    if (/android:debuggable\s*=\s*["']true["']/i.test(manifest)) {
      findings.push({
        severity: 'critical', title: 'android:debuggable="true" en Manifest',
        description: 'La app es debuggable. Un atacante puede adjuntar un debugger y extraer datos en tiempo real.',
        file: 'android/app/src/main/AndroidManifest.xml', line: null, code: null,
        fix: 'Elimina android:debuggable del Manifest. Gradle lo gestiona automáticamente por buildType.',
        cve: 'CWE-489: Active Debug Code',
      });
    }
  } else {
    findings.push({
      severity: 'medium', title: 'AndroidManifest.xml no encontrado',
      description: 'No se pudo analizar la configuración de Android.',
      file: null, line: null, code: null, fix: 'Verifica la ruta del proyecto Flutter.', cve: null,
    });
  }

  // ── iOS ───────────────────────────────────────────────────────────────────
  const plistPath = path.join(projectRoot, 'ios', 'Runner', 'Info.plist');
  let plist = '';
  try { plist = readFileSync(plistPath, 'utf8'); } catch {}

  if (plist) {
    // ATS disabled
    if (/NSAppTransportSecurity[\s\S]*?NSAllowsArbitraryLoads[\s\S]*?<true\s*\/>/i.test(plist)) {
      findings.push({
        severity: 'high', title: 'NSAllowsArbitraryLoads=true (ATS desactivado)',
        description: 'App Transport Security está desactivado. La app puede hacer peticiones HTTP sin cifrado.',
        file: 'ios/Runner/Info.plist', line: null, code: null,
        fix: 'Elimina NSAllowsArbitraryLoads o configura excepciones específicas por dominio.',
        cve: 'CWE-319',
      });
    }

    // No privacy keys — only flag if the app requests the resource but lacks its description string
    const privacyChecks = [
      { trigger: 'NSCameraUsage',      key: 'NSCameraUsageDescription' },
      { trigger: 'NSMicrophoneUsage',  key: 'NSMicrophoneUsageDescription' },
      { trigger: 'NSLocationWhenIn',   key: 'NSLocationWhenInUseUsageDescription' },
    ];
    const missingKeys = privacyChecks
      .filter(({ trigger, key }) => plist.includes(trigger) && !plist.includes(key))
      .map(({ key }) => key);
    for (const k of missingKeys) {
      findings.push({
        severity: 'low', title: `Falta ${k} en Info.plist`,
        description: 'iOS requiere strings de justificación para accesos a hardware. Sin ellos Apple rechazará la app.',
        file: 'ios/Runner/Info.plist', line: null, code: null,
        fix: `Añade <key>${k}</key><string>Razón clara del uso</string>`,
        cve: null,
      });
    }
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de configuración de plataforma` : 'Configuración de plataforma correcta' };
}
