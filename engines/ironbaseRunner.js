/**
 * engines/ironbaseRunner.js
 * Node.js wrapper for IronBase Linux Hardening Engine.
 * Executes IronBase Bash modules via child_process and parses JSON reports.
 */

import { exec } from 'child_process';
import { readFileSync, existsSync, readdirSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IRONBASE_DIR = path.join(__dirname, 'ironbase');
const IRONBASE_CMD = path.join(IRONBASE_DIR, 'cmd', 'ironbase');

// Module metadata for the dashboard
const INFRA_MODULES = {
  'secure-vps':    { id: 'secure-vps',    name: 'Seguridad VPS',           description: 'Evaluación integral de exposición del servidor' },
  'ssh':           { id: 'ssh',           name: 'SSH Hardening',           description: 'Configuración segura de SSH' },
  'firewall':      { id: 'firewall',      name: 'Firewall (UFW)',          description: 'Auditoría y hardening de firewall' },
  'filesystem':    { id: 'filesystem',    name: 'Permisos Filesystem',     description: 'Permisos de archivos y directorios críticos' },
  'vulnerability': { id: 'vulnerability', name: 'Vulnerabilidades',        description: 'Escaneo de paquetes vulnerables y kernel' },
  'users':         { id: 'users',         name: 'Usuarios & Privilegios',  description: 'Detección de usuarios y escalada de privilegios' },
  'system':        { id: 'system',        name: 'Sistema',                 description: 'Configuración del OS, kernel y actualizaciones' },
  'network':       { id: 'network',       name: 'Red & Puertos',           description: 'Exposición de red y puertos abiertos' },
  'services':      { id: 'services',      name: 'Servicios',               description: 'Docker, auditd, journald y servicios activos' },
};

/**
 * Check if IronBase engine is available
 */
export function isIronbaseAvailable() {
  return existsSync(IRONBASE_CMD);
}

/**
 * Get available infrastructure modules
 */
export function getInfraModules() {
  return Object.values(INFRA_MODULES);
}

/**
 * Execute an IronBase scan for specific modules
 * @param {string[]} modules - Module IDs to scan
 * @returns {Promise<Object>} - Parsed scan results in Fractia format
 */
export async function runInfraScan(modules = Object.keys(INFRA_MODULES)) {
  const startTime = Date.now();

  // Validate modules
  const validModules = modules.filter(m => INFRA_MODULES[m]);
  if (validModules.length === 0) {
    throw new Error('No valid infrastructure modules selected.');
  }

  // Run each module individually and collect results
  const results = await Promise.all(
    validModules.map(mod => runSingleModule(mod))
  );

  // Calculate risk score
  const riskScore = calculateInfraRiskScore(results);
  const summary = generateInfraSummary(results, riskScore);

  return {
    summary,
    risk_score: riskScore,
    modules: results,
    meta: {
      generatedAt: new Date().toISOString(),
      engine: 'ironbase',
      scanDurationMs: Date.now() - startTime,
    },
  };
}

/**
 * Run a single IronBase module and return results in Fractia format
 */
async function runSingleModule(moduleId) {
  const meta = INFRA_MODULES[moduleId];

  try {
    // Execute IronBase scan for this specific module
    const { stdout, reportJson } = await executeIronbase(moduleId);

    // Parse findings from the report JSON
    const findings = parseIronbaseFindings(reportJson, moduleId);

    // Determine severity from findings
    const severity = determineSeverity(findings);
    const score = calculateModuleScore(findings);

    return {
      id: moduleId,
      name: meta.name,
      severity,
      score,
      findings,
      recommendations: generateRecommendations(findings),
      _engine: 'ironbase',
    };
  } catch (err) {
    console.error(`[ironbase:${moduleId}] Error:`, err.message);
    return {
      id: moduleId,
      name: meta.name,
      severity: 'low',
      score: 100,
      findings: [{
        type: 'info',
        title: 'Módulo no pudo ejecutarse',
        description: `Error: ${err.message}. Este módulo requiere ejecución con privilegios en un servidor Linux.`,
        code_example: null,
        cve: null,
      }],
      recommendations: ['Ejecutar Fractia directamente en el servidor objetivo con permisos de root.'],
      _engine: 'ironbase',
      _error: true,
    };
  }
}

/**
 * Execute the IronBase CLI for a single module
 */
function executeIronbase(moduleId) {
  return new Promise((resolve, reject) => {
    const cmd = `bash "${IRONBASE_CMD}" scan --module ${moduleId}`;
    const opts = {
      cwd: IRONBASE_DIR,
      timeout: 60000,
      env: { ...process.env, TERM: 'dumb' },
      maxBuffer: 1024 * 1024 * 5,
    };

    exec(cmd, opts, (error, stdout, stderr) => {
      // IronBase returns exit code 1 when findings exist, which is normal
      const combinedOutput = stdout + '\n' + stderr;

      // Try to find and read the JSON report from the latest run
      const latestDir = findLatestRunDir();
      let reportJson = null;

      if (latestDir) {
        const jsonPath = path.join(latestDir, 'report.json');
        if (existsSync(jsonPath)) {
          try {
            reportJson = JSON.parse(readFileSync(jsonPath, 'utf8'));
          } catch { /* parse error, use stdout fallback */ }
        }
      }

      resolve({ stdout: combinedOutput, reportJson });
    });
  });
}

/**
 * Find the latest run directory in IronBase output
 */
function findLatestRunDir() {
  const runsDir = path.join(IRONBASE_DIR, 'output', 'runs');
  if (!existsSync(runsDir)) return null;

  const dirs = readdirSync(runsDir)
    .filter(d => /^\d{4}-\d{2}-\d{2}_/.test(d))
    .sort()
    .reverse();

  return dirs.length > 0 ? path.join(runsDir, dirs[0]) : null;
}

/**
 * Parse IronBase JSON report findings into Fractia format
 */
function parseIronbaseFindings(reportJson, moduleId) {
  if (!reportJson || !reportJson.findings) return [];

  return reportJson.findings
    .filter(f => !moduleId || f.module === moduleId)
    .map(f => ({
      type: mapIronbaseSeverityToType(f.severity, f.status),
      title: f.title || 'Finding sin título',
      description: f.description || '',
      code_example: f.evidence || null,
      cve: null,
      _ironbase: {
        id: f.id,
        severity: f.severity,
        status: f.status,
        remediation: f.remediation,
        module: f.module,
      },
    }));
}

/**
 * Map IronBase severity/status to Fractia finding type
 */
function mapIronbaseSeverityToType(severity, status) {
  if (status === 'FAIL') {
    if (severity === 'CRITICAL' || severity === 'HIGH') return 'vulnerability';
    return 'warning';
  }
  if (status === 'WARN') return 'warning';
  return 'info';
}

/**
 * Determine overall module severity from findings
 */
function determineSeverity(findings) {
  const hasVulns = findings.some(f => f.type === 'vulnerability');
  const hasWarns = findings.some(f => f.type === 'warning');

  if (hasVulns) {
    const hasCritical = findings.some(f => f._ironbase?.severity === 'CRITICAL');
    if (hasCritical) return 'critical';
    return 'high';
  }
  if (hasWarns) return 'medium';
  return 'ok';
}

/**
 * Calculate module score (0-100, lower is worse)
 */
function calculateModuleScore(findings) {
  const WEIGHTS = { CRITICAL: 25, HIGH: 15, MEDIUM: 7, LOW: 2, INFO: 0 };
  let penalty = 0;

  for (const f of findings) {
    const sev = f._ironbase?.severity || 'INFO';
    if (f._ironbase?.status === 'FAIL' || f._ironbase?.status === 'WARN') {
      penalty += WEIGHTS[sev] || 0;
    }
  }

  return Math.max(0, 100 - penalty);
}

/**
 * Generate recommendations from findings
 */
function generateRecommendations(findings) {
  const recs = new Set();
  for (const f of findings) {
    if (f._ironbase?.remediation) {
      recs.add(f._ironbase.remediation);
    }
  }
  return [...recs];
}

/**
 * Calculate overall infrastructure risk score
 */
function calculateInfraRiskScore(results) {
  const WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, ok: 0 };
  const total = results.reduce((sum, r) => sum + (WEIGHTS[r.severity] || 0), 0);
  return Math.min(100, total);
}

/**
 * Generate infrastructure summary
 */
function generateInfraSummary(results, riskScore) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) counts[r.severity] = (counts[r.severity] || 0) + 1;

  const critMods = results.filter(r => r.severity === 'critical').map(r => r.name);
  const highMods = results.filter(r => r.severity === 'high').map(r => r.name);

  let summary = `Infrastructure risk score ${riskScore}/100 across ${results.length} modules. `;
  if (counts.critical > 0) summary += `CRITICAL issues in: ${critMods.join(', ')}. `;
  if (counts.high > 0) summary += `HIGH severity in: ${highMods.join(', ')}. `;
  if (counts.critical === 0 && counts.high === 0) summary += 'No critical or high severity issues detected. ';
  summary += `${counts.ok} modules passed cleanly.`;

  return summary;
}

/**
 * Parse IronBase console output as fallback when JSON report is not available
 * Extracts findings from the colored terminal output
 */
export function parseConsoleOutput(stdout) {
  const findings = [];
  // Match patterns like: [FAIL] [HIGH] Title (ID)
  const pattern = /\[(PASS|WARN|FAIL)\]\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)\s*\(([^)]+)\)/g;
  let match;

  while ((match = pattern.exec(stdout)) !== null) {
    const [, status, severity, title, id] = match;
    findings.push({
      type: mapIronbaseSeverityToType(severity, status),
      title: title.trim(),
      description: `Status: ${status} | Severity: ${severity}`,
      code_example: null,
      cve: null,
      _ironbase: { id, severity, status, remediation: '', module: 'unknown' },
    });
  }

  return findings;
}
