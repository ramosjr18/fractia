/**
 * pubspec.yaml / pubspec.lock parser
 */
import { readFileSync } from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';

// Known vulnerable / sensitive packages
const VULNERABLE_PACKAGES = [
  { name: 'http',              maxVersion: '0.13.6', reason: 'Versiones <1.0.0 no soportan custom HttpClient para SSL pinning', severity: 'high' },
  { name: 'shared_preferences', maxVersion: null,     reason: 'Almacena datos en texto plano — nunca usar para tokens o datos sensibles', severity: 'critical' },
  { name: 'path_provider',     maxVersion: '2.0.0',  reason: 'Versiones <2.0 tienen path traversal en ciertas plataformas', severity: 'medium' },
  { name: 'webview_flutter',   maxVersion: '4.0.0',  reason: 'Versiones <4.0 tienen XSS en ciertos casos', severity: 'high' },
  { name: 'url_launcher',      maxVersion: '6.1.0',  reason: 'Versiones <6.1 tienen intent injection en Android', severity: 'high' },
  { name: 'flutter_web_auth',  maxVersion: null,      reason: 'Deprecado — usar flutter_web_auth_2', severity: 'low' },
];

// Security packages that SHOULD be present
const SECURITY_PACKAGES = [
  { name: 'flutter_secure_storage', reason: 'Almacenamiento cifrado para tokens y credenciales' },
  { name: 'local_auth',             reason: 'Autenticación biométrica para operaciones sensibles' },
];

// Dev packages that should NOT be in production deps
const DEV_ONLY_PACKAGES = ['mockito', 'faker', 'test', 'flutter_test'];

export function parsePubspec(projectRoot) {
  const pubspecPath = path.join(projectRoot, 'pubspec.yaml');
  let raw;
  try {
    raw = readFileSync(pubspecPath, 'utf8');
  } catch {
    return null;
  }

  let parsed;
  try {
    parsed = parseYaml(raw);
  } catch {
    return null;
  }

  const deps    = parsed.dependencies    || {};
  const devDeps = parsed.dev_dependencies || {};
  const allDeps = { ...deps, ...devDeps };

  // Normalize version strings
  const depList = Object.entries(deps).map(([name, ver]) => ({
    name,
    version: typeof ver === 'string' ? ver : (ver?.version || 'any'),
    isDev:   false,
  }));
  const devDepList = Object.entries(devDeps).map(([name, ver]) => ({
    name,
    version: typeof ver === 'string' ? ver : (ver?.version || 'any'),
    isDev:   true,
  }));

  return {
    name:         parsed.name || 'unknown',
    version:      parsed.version || '0.0.0',
    sdkConstraint: parsed.environment?.sdk || 'unknown',
    dependencies: depList,
    devDependencies: devDepList,
    allDeps:      [...depList, ...devDepList],
    raw:          parsed,
    hasDep:       (name) => name in deps || name in devDeps,
    hasProdDep:   (name) => name in deps,
  };
}

export function auditPubspec(pubspec) {
  if (!pubspec) return { findings: [], missing: [] };

  const findings = [];
  const missing  = [];

  // Check for vulnerable packages
  for (const vuln of VULNERABLE_PACKAGES) {
    if (pubspec.hasDep(vuln.name)) {
      findings.push({
        package:  vuln.name,
        severity: vuln.severity,
        reason:   vuln.reason,
        type:     'vulnerable',
      });
    }
  }

  // Check for missing security packages
  for (const sec of SECURITY_PACKAGES) {
    if (!pubspec.hasDep(sec.name)) {
      missing.push({
        package:  sec.name,
        severity: 'high',
        reason:   sec.reason,
        type:     'missing',
      });
    }
  }

  // Check for dev packages in prod deps
  for (const devPkg of DEV_ONLY_PACKAGES) {
    if (pubspec.hasProdDep(devPkg)) {
      findings.push({
        package:  devPkg,
        severity: 'low',
        reason:   'Paquete de desarrollo en dependencias de producción',
        type:     'dev_in_prod',
      });
    }
  }

  // Check for unpinned versions
  const unpinned = pubspec.dependencies.filter(d => {
    const v = d.version;
    return typeof v === 'string' && (v.startsWith('^') || v === 'any' || v === '');
  });

  return { findings, missing, unpinned };
}
