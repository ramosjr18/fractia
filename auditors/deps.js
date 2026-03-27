import { execFile } from 'child_process';
import path from 'path';
import fs from 'fs/promises';
import { readFile, BACKEND_ROOT } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Known vulnerable Node.js packages ───────────────────────────────────────

const KNOWN_NODE_ISSUES = {
  'multer':        { below: '1.4.5-lts.2', issue: 'ReDoS vulnerability in content-type parsing',   severity: 'high',     cve: 'CVE-2022-24434'  },
  'jsonwebtoken':  { below: '9.0.0',        issue: 'Algorithm confusion vulnerability',              severity: 'critical', cve: 'CVE-2022-23529'  },
  'node-fetch':    { below: '2.6.7',        issue: 'Exposure of sensitive information',              severity: 'high',     cve: 'CVE-2022-0235'   },
  'axios':         { below: '1.6.0',        issue: 'SSRF and credential leakage',                   severity: 'high',     cve: 'CVE-2023-45857'  },
  'lodash':        { below: '4.17.21',      issue: 'Prototype pollution',                           severity: 'high',     cve: 'CVE-2021-23337'  },
  'minimist':      { below: '1.2.6',        issue: 'Prototype pollution',                           severity: 'medium',   cve: 'CVE-2021-44906'  },
  'express':       { below: '4.19.0',       issue: 'Path traversal via open redirect',              severity: 'medium',   cve: 'CVE-2024-29041'  },
  'sharp':         { below: '0.32.6',       issue: 'Heap buffer overflow',                          severity: 'high',     cve: 'CVE-2023-4863'   },
  'semver':        { below: '7.5.2',        issue: 'ReDoS vulnerability',                           severity: 'medium',   cve: 'CVE-2022-25883'  },
  'tough-cookie':  { below: '4.1.3',        issue: 'Prototype pollution',                           severity: 'medium',   cve: 'CVE-2023-26136'  },
};

// ─── Known vulnerable Python packages ────────────────────────────────────────

const KNOWN_PYTHON_ISSUES = {
  'cryptography':   { below: '41.0.6', issue: 'NULL pointer dereference in PKCS12 parsing',       severity: 'high',     cve: 'CVE-2023-49083'  },
  'pillow':         { below: '10.0.1', issue: 'Heap buffer overflow in image processing',          severity: 'high',     cve: 'CVE-2023-44271'  },
  'requests':       { below: '2.31.0', issue: 'Credentials leaked in redirects',                   severity: 'medium',   cve: 'CVE-2023-32681'  },
  'pyjwt':          { below: '2.4.0',  issue: 'Algorithm confusion / alg:none attack',             severity: 'critical', cve: 'CVE-2022-29217'  },
  'sqlalchemy':     { below: '1.4.49', issue: 'SQL injection via ORM parameter bypass',            severity: 'high',     cve: 'CVE-2023-30608'  },
  'starlette':      { below: '0.27.0', issue: 'Path traversal in StaticFiles middleware',          severity: 'high',     cve: 'CVE-2023-29159'  },
  'fastapi':        { below: '0.99.0', issue: 'Dependency on vulnerable Starlette version',        severity: 'medium',   cve: null              },
  'aiohttp':        { below: '3.8.5',  issue: 'Request smuggling / header injection',              severity: 'high',     cve: 'CVE-2023-37276'  },
  'paramiko':       { below: '3.4.0',  issue: 'Prefix truncation attack (Terrapin)',               severity: 'medium',   cve: 'CVE-2023-48795'  },
  'urllib3':        { below: '2.0.7',  issue: 'Header injection via CRLF characters',              severity: 'medium',   cve: 'CVE-2023-45803'  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function semverBelow(version, threshold) {
  const normalize = v => v.replace(/[-+].*$/, '').split('.').map(n => parseInt(n) || 0);
  const [v1, v2, v3] = normalize(version);
  const [t1, t2, t3] = normalize(threshold);
  if (v1 !== t1) return v1 < t1;
  if (v2 !== t2) return v2 < t2;
  return v3 < t3;
}

async function runNpmAudit(cwd) {
  return new Promise((resolve) => {
    execFile('npm', ['audit', '--json'], { cwd, timeout: 30000 }, (_err, stdout) => {
      try { resolve(JSON.parse(stdout || '{}')); }
      catch { resolve(null); }
    });
  });
}

// ─── Python audit ─────────────────────────────────────────────────────────────

async function auditPython(reqPath) {
  const findings = [];
  const recommendations = [];

  // Read requirements.txt
  let reqContent = null;
  try { reqContent = await fs.readFile(reqPath, 'utf8'); } catch (_) { /* skip */ }

  if (!reqContent) {
    findings.push({
      type: 'warning',
      title: 'No se encontró requirements.txt',
      description: 'No se pudo leer requirements.txt. Sin un archivo de dependencias, es imposible auditar versiones vulnerables.',
      code_example: 'pip freeze > requirements.txt',
      cve: null,
    });
  } else {
    // Parse pinned packages
    const pinned = [];
    const unpinned = [];

    for (const line of reqContent.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

      const exactMatch = trimmed.match(/^([\w.-]+)==([\d.]+)/i);
      if (exactMatch) {
        pinned.push({ name: exactMatch[1].toLowerCase(), version: exactMatch[2] });
      } else if (/^[\w.-]+[>=<!~]/i.test(trimmed)) {
        unpinned.push(trimmed.split(/[>=<!~]/)[0].trim());
      } else if (/^[\w.-]+$/i.test(trimmed)) {
        unpinned.push(trimmed);
      }
    }

    // Check known vulnerable versions
    for (const { name, version } of pinned) {
      const issue = KNOWN_PYTHON_ISSUES[name];
      if (issue && semverBelow(version, issue.below)) {
        findings.push({
          type: 'vulnerability',
          title: `${name}==${version} tiene una vulnerabilidad conocida (${issue.severity.toUpperCase()})`,
          description: issue.issue,
          code_example: `pip install "${name}>=${issue.below}"`,
          cve: issue.cve,
        });
      }
    }

    // Warn about unpinned packages
    if (unpinned.length > 5) {
      findings.push({
        type: 'warning',
        title: `${unpinned.length} dependencias sin versión exacta pinned`,
        description: `Paquetes sin == exacto: ${unpinned.slice(0, 5).join(', ')}${unpinned.length > 5 ? '...' : ''}. Sin versiones pinned, una instalación futura puede traer versiones vulnerables silenciosamente.`,
        code_example: 'pip freeze > requirements.txt  # Genera un lockfile exacto',
        cve: null,
      });
    }

    // Suggest pip-audit
    findings.push({
      type: 'info',
      title: 'Ejecuta pip-audit para un escaneo completo de vulnerabilidades',
      description: 'Fractia solo verifica una lista curada de paquetes conocidos. pip-audit compara contra PyPI Advisory Database y OSV de forma exhaustiva.',
      code_example: 'pip install pip-audit\npip-audit -r requirements.txt',
      cve: null,
    });
  }

  recommendations.push(
    'Usa pip-audit como gate en tu CI/CD — falla el pipeline ante vulnerabilidades críticas/altas.',
    'Pin todas las dependencias con == en requirements.txt (usa pip freeze).',
    'Usa dependabot o renovate para PRs automáticas de actualizaciones.',
    'Separa requirements.txt (prod) de requirements-dev.txt (dev/test) para reducir la superficie de ataque.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : findings.some(f => f.type === 'warning') ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20);

  return { id: 'deps', name: 'Dependencias', severity, score, findings, recommendations };
}

// ─── Node.js audit ────────────────────────────────────────────────────────────

async function auditNode(root) {
  const findings = [];
  const recommendations = [];

  const auditData = await runNpmAudit(root);

  if (auditData && auditData.vulnerabilities) {
    const vulns = Object.values(auditData.vulnerabilities);
    const bySeverity = { critical: [], high: [], moderate: [], low: [] };
    for (const v of vulns) {
      const sev = v.severity?.toLowerCase();
      if (bySeverity[sev]) bySeverity[sev].push(v);
    }

    const total = auditData.metadata?.vulnerabilities;
    if (total) {
      findings.push({
        type: total.critical > 0 || total.high > 0 ? 'vulnerability' : 'warning',
        title: `npm audit found: ${total.critical || 0} critical, ${total.high || 0} high, ${total.moderate || 0} moderate, ${total.low || 0} low`,
        description: `Total packages audited: ${total.total || 'unknown'}. Run \`npm audit fix\` to resolve auto-fixable issues.`,
        code_example: null,
        cve: null,
      });
    }

    for (const v of [...bySeverity.critical, ...bySeverity.high].slice(0, 5)) {
      const via = Array.isArray(v.via) ? v.via.find(x => typeof x === 'object') : null;
      findings.push({
        type: 'vulnerability',
        title: `${v.name}@${v.range || 'unknown'} — ${v.severity?.toUpperCase()} vulnerability`,
        description: via ? `${via.title || 'Vulnerability'}. ${via.url || ''}` : `Vulnerable package: ${v.name}`,
        code_example: `npm audit fix${v.fixAvailable ? '' : ' --force  # manual review required'}`,
        cve: via?.cve?.[0] || null,
      });
    }
  } else {
    const pkgPath = path.join(root, 'package.json');
    const pkgContent = await readFile(pkgPath);

    if (pkgContent) {
      const pkg = JSON.parse(pkgContent);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      for (const [name, range] of Object.entries(allDeps)) {
        if (KNOWN_NODE_ISSUES[name]) {
          const issue = KNOWN_NODE_ISSUES[name];
          const version = range.replace(/^[\^~>=<\s]+/, '');
          if (semverBelow(version, issue.below)) {
            findings.push({
              type: 'vulnerability',
              title: `${name}@${version} has a known ${issue.severity} vulnerability`,
              description: issue.issue,
              code_example: `npm install ${name}@latest`,
              cve: issue.cve,
            });
          }
        }
      }

      findings.push({
        type: 'info',
        title: 'npm audit could not run (no lockfile or network issue)',
        description: 'Run `npm audit` manually in the backend directory for a complete vulnerability report.',
        code_example: 'cd backend && npm audit',
        cve: null,
      });
    }
  }

  recommendations.push(
    'Run `npm audit fix` to resolve auto-fixable vulnerabilities.',
    'Set up `npm audit` as a CI/CD gate — fail the build on critical/high severity issues.',
    'Use Dependabot or Renovate to automate dependency update PRs.',
    'Pin exact dependency versions in production (use package-lock.json).',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : findings.some(f => f.type === 'warning') ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20);

  return { id: 'deps', name: 'Dependencias', severity, score, findings, recommendations };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, requirementsTxtPath, root } = await detectProjectType();
  if (isPython) return auditPython(requirementsTxtPath);
  return auditNode(BACKEND_ROOT());
}
