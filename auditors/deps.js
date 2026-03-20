import { execFile } from 'child_process';
import path from 'path';
import { readFile, BACKEND_ROOT } from '../utils/fileScanner.js';

// Fallback: known vulnerable version ranges
const KNOWN_ISSUES = {
  'multer': { below: '1.4.5-lts.2', issue: 'ReDoS vulnerability in content-type parsing', severity: 'high', cve: 'CVE-2022-24434' },
};

function semverBelow(version, threshold) {
  // Simple major.minor.patch comparison (handles lts variants by numeric comparison)
  const normalize = v => v.replace(/-lts\.\d+$/, '').split('.').map(Number);
  const [v1, v2, v3] = normalize(version);
  const [t1, t2, t3] = normalize(threshold);
  if (v1 !== t1) return v1 < t1;
  if (v2 !== t2) return v2 < t2;
  return v3 < t3;
}

async function runNpmAudit(cwd) {
  return new Promise((resolve) => {
    execFile('npm', ['audit', '--json'], { cwd, timeout: 30000 }, (_err, stdout) => {
      try {
        resolve(JSON.parse(stdout || '{}'));
      } catch {
        resolve(null);
      }
    });
  });
}

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const root = BACKEND_ROOT();

  // --- npm audit ---
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
      const summary = `npm audit found: ${total.critical || 0} critical, ${total.high || 0} high, ${total.moderate || 0} moderate, ${total.low || 0} low`;
      findings.push({
        type: total.critical > 0 || total.high > 0 ? 'vulnerability' : 'warning',
        title: summary,
        description: `Total packages audited: ${total.total || 'unknown'}. Run \`npm audit fix\` to resolve auto-fixable issues.`,
        code_example: null,
        cve: null,
      });
    }

    // Report critical and high individually
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
    // Fallback: parse package.json manually
    const pkgPath = path.join(root, 'package.json');
    const pkgContent = await readFile(pkgPath);

    if (pkgContent) {
      const pkg = JSON.parse(pkgContent);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      for (const [name, range] of Object.entries(allDeps)) {
        if (KNOWN_ISSUES[name]) {
          const issue = KNOWN_ISSUES[name];
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
