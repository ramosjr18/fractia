/**
 * Flutter/Dart Security Engine — Pilar D: Mobile Audit
 * Orquestador de los 10 módulos de análisis estático para proyectos Flutter.
 *
 * Uso:
 *   import { runMobileAudit, MOBILE_MODULES } from './flutterRunner.js';
 *   const results = await runMobileAudit(modules, flutterRoot, hooks);
 */
import path from 'path';
import { existsSync } from 'fs';
import { findDartFiles } from './flutter/utils/dartParser.js';
import { parsePubspec }   from './flutter/utils/pubspecParser.js';

// ── Module registry ───────────────────────────────────────────────────────────
export const MOBILE_MODULES = [
  'auth', 'network', 'storage', 'deeplinks', 'crypto',
  'platform', 'deps', 'obfuscation', 'logging', 'state',
];

const MODULE_LOADERS = {
  auth:        () => import('./flutter/scanners/auth.dart.js'),
  network:     () => import('./flutter/scanners/network.dart.js'),
  storage:     () => import('./flutter/scanners/storage.dart.js'),
  deeplinks:   () => import('./flutter/scanners/deeplinks.dart.js'),
  crypto:      () => import('./flutter/scanners/crypto.dart.js'),
  platform:    () => import('./flutter/scanners/platform.dart.js'),
  deps:        () => import('./flutter/scanners/deps.dart.js'),
  obfuscation: () => import('./flutter/scanners/obfuscation.dart.js'),
  logging:     () => import('./flutter/scanners/logging.dart.js'),
  state:       () => import('./flutter/scanners/state.dart.js'),
};

// ── Hooks interface ───────────────────────────────────────────────────────────
// hooks.onModuleStart({ module, name, index, total })
// hooks.onModuleComplete({ module, name, result, index, total, ms })

// ── Main runner ───────────────────────────────────────────────────────────────
export async function runMobileAudit(modules = MOBILE_MODULES, flutterRoot, hooks = {}) {
  // 1. Discover dart files
  const dartFiles = findDartFiles(flutterRoot);

  // 2. Parse pubspec.yaml
  const pubspec = parsePubspec(flutterRoot);

  const context = { dartFiles, pubspec, projectRoot: flutterRoot };
  const results = [];
  const total   = modules.length;

  // 3. Run scanners (sequentially to avoid garbled spinner output)
  for (let i = 0; i < modules.length; i++) {
    const moduleId = modules[i];
    const loader   = MODULE_LOADERS[moduleId];
    if (!loader) continue;

    const { meta, scan } = await loader();
    hooks.onModuleStart?.({ module: moduleId, name: meta.name, index: i, total });

    const t0 = Date.now();
    let result;
    try {
      result = await scan(context);
    } catch (err) {
      result = {
        module:   moduleId,
        name:     meta.name,
        severity: 'medium',
        findings: [{ severity: 'medium', title: `Error al ejecutar scanner: ${err.message}`,
          description: err.stack, file: null, line: null, code: null, fix: null, cve: null }],
        passed:  false,
        summary: `Error al ejecutar el módulo ${moduleId}`,
      };
    }
    const ms = Date.now() - t0;
    results.push(result);
    hooks.onModuleComplete?.({ module: moduleId, name: meta.name, result, index: i, total, ms });
  }

  return {
    results,
    dartFilesScanned: dartFiles.length,
    pubspecFound:     !!pubspec,
    ...generateSummary(results),
  };
}

// ── Summary ───────────────────────────────────────────────────────────────────
function generateSummary(results) {
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const counts   = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };

  let worstSeverity = 'ok';
  let totalFindings = 0;

  for (const r of results) {
    counts[r.severity] = (counts[r.severity] || 0) + 1;
    totalFindings += r.findings?.length || 0;
    if (SEV_RANK[r.severity] > SEV_RANK[worstSeverity]) {
      worstSeverity = r.severity;
    }
  }

  // Risk score 0-100 (higher = more risk)
  const riskScore = Math.min(100, Math.round(
    (counts.critical * 25 + counts.high * 12 + counts.medium * 5 + counts.low * 2)
  ));

  return { worstSeverity, totalFindings, counts, riskScore };
}

export function isMobileProject(dir) {
  return existsSync(path.join(dir, 'pubspec.yaml')) && existsSync(path.join(dir, 'lib'));
}
