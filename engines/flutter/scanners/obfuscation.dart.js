/**
 * obfuscation.dart.js — Ofuscación & Build Security
 */
import { readFileSync, readdirSync } from 'fs';
import path from 'path';

export const meta = { id: 'obfuscation', name: 'Obfuscation & Build Security', severity: 'medium', pilar: 'Mobile' };

export async function scan({ dartFiles, pubspec, projectRoot }) {
  const findings = [];

  // ── Check build scripts for --obfuscate flag ──────────────────────────────
  const buildScripts = [
    path.join(projectRoot, 'Makefile'),
    path.join(projectRoot, 'scripts', 'build.sh'),
    path.join(projectRoot, 'build.sh'),
    path.join(projectRoot, '.github', 'workflows', 'build.yml'),
    path.join(projectRoot, '.github', 'workflows', 'release.yml'),
  ];

  let foundObfuscate = false;
  for (const scriptPath of buildScripts) {
    try {
      const content = readFileSync(scriptPath, 'utf8');
      if (/--obfuscate|--split-debug-info/i.test(content)) {
        foundObfuscate = true;
        break;
      }
    } catch {}
  }

  if (!foundObfuscate) {
    findings.push({
      severity: 'medium', title: 'Sin --obfuscate en scripts de build',
      description: 'Sin ofuscación, el APK/IPA es fácilmente reversible. Un atacante puede extraer nombres de clases, endpoints, lógica de negocio y strings sensibles.',
      file: null, line: null, code: null,
      fix: 'Añade --obfuscate --split-debug-info=build/app/outputs/symbols en tu comando flutter build apk/appbundle/ipa.',
      cve: 'CWE-656: Reliance on Security Through Obscurity',
    });
  }

  // ── ProGuard / R8 for Android ─────────────────────────────────────────────
  const proguardPath = path.join(projectRoot, 'android', 'app', 'proguard-rules.pro');
  let hasProguard = false;
  try { readFileSync(proguardPath, 'utf8'); hasProguard = true; } catch {}

  const buildGradlePath = path.join(projectRoot, 'android', 'app', 'build.gradle');
  let buildGradle = '';
  try { buildGradle = readFileSync(buildGradlePath, 'utf8'); } catch {}

  if (buildGradle && !/minifyEnabled\s+true/i.test(buildGradle)) {
    findings.push({
      severity: 'medium', title: 'minifyEnabled=false en build.gradle',
      description: 'R8/ProGuard no está activo. El código Java/Kotlin no está minificado ni ofuscado en el APK.',
      file: 'android/app/build.gradle', line: null, code: null,
      fix: 'En la sección release: minifyEnabled true, shrinkResources true, proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro"',
      cve: 'CWE-656',
    });
  }

  // ── Sensitive assets not encrypted ───────────────────────────────────────
  let assetFiles = [];
  try { assetFiles = readdirSync(path.join(projectRoot, 'assets')); } catch {}
  const sensitiveAssets = assetFiles.filter(f => /config|secret|key|prod|credentials/i.test(f) && /\.json|\.yaml|\.env/i.test(f));
  for (const asset of sensitiveAssets) {
    findings.push({
      severity: 'high', title: `Asset sensible incluido sin cifrar: ${asset}`,
      description: `El archivo assets/${asset} puede contener configuración sensible accesible tras descompilar el APK.`,
      file: `assets/${asset}`, line: null, code: null,
      fix: 'Elimina los archivos de configuración sensibles de assets. Usa variables de entorno o flutter_dotenv con cifrado.',
      cve: 'CWE-540: Inclusion of Sensitive Information in Source Code',
    });
  }

  return buildResult(findings);
}

function buildResult(findings) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const maxSev = findings.reduce((b, f) => rank[f.severity] > rank[b] ? f.severity : b, 'ok');
  return { module: meta.id, name: meta.name, severity: findings.length ? maxSev : 'ok', findings, passed: findings.length === 0,
    summary: findings.length ? `${findings.length} problema(s) de ofuscación/build` : 'Build security configurado correctamente' };
}
