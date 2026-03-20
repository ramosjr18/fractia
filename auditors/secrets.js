import path from 'path';
import { readFile, grepFiles, BACKEND_ROOT, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

const PATTERNS = [
  { regex: /(['"`])sk-[A-Za-z0-9]{20,}\1/,                        label: 'Hardcoded OpenAI/Stripe API key',        severity: 'critical' },
  { regex: /(['"`])AKIA[A-Z0-9]{16}\1/,                            label: 'Hardcoded AWS Access Key',              severity: 'critical' },
  { regex: /(['"`])Bearer [A-Za-z0-9._\-]{20,}\1/,                 label: 'Hardcoded Bearer token',                severity: 'critical' },
  { regex: /(['"`])ghp_[A-Za-z0-9]{36}\1/,                         label: 'Hardcoded GitHub Personal Access Token', severity: 'critical' },
  { regex: /jwt\.sign\([^)]+,\s*['"`][^'"`]{6,}['"`]/,             label: 'Hardcoded JWT signing secret in jwt.sign()', severity: 'high' },
  { regex: /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|API_KEY|SALT)\b.*\|\|\s*['"`][^'"`]{4,}['"`]/i, label: 'Fallback hardcoded secret via || operator', severity: 'high' },
  { regex: /password\s*[:=]\s*['"`][^'"`]{6,}['"`]/i,              label: 'Hardcoded password string',             severity: 'high' },
  { regex: /secret\s*[:=]\s*['"`][^'"`]{6,}['"`]/i,                label: 'Hardcoded secret string',               severity: 'medium' },
  { regex: /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9._\-]{10,}['"`]/i, label: 'Hardcoded API key',                   severity: 'high' },
];

function redact(line) {
  // Replace quoted values with [REDACTED]
  return line.replace(/(['"`])[^'"`]{4,}\1/g, '\'[REDACTED]\'');
}

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const backendSrc = BACKEND_SRC();
  const backendRoot = BACKEND_ROOT();

  // --- Layer 1: Scan source files for hardcoded credential patterns ---
  const sourceMatches = await grepFiles(backendSrc, PATTERNS.map(p => p.regex), {
    extensions: ['.js'],
    contextLines: 1,
    excludeDirs: ['node_modules', '__tests__', 'tests'],
  });

  // Group matches by pattern label to avoid 10 identical finding titles
  const grouped = new Map();
  for (const match of sourceMatches) {
    const matchedPattern = PATTERNS.find(p => p.regex.test(match.line));
    if (!matchedPattern) continue;
    if (match.filePath.includes('.test.') || match.filePath.includes('.spec.')) continue;
    if (match.line.trim().startsWith('//') || match.line.trim().startsWith('*')) continue;

    const key = matchedPattern.label;
    if (!grouped.has(key)) grouped.set(key, { pattern: matchedPattern, matches: [] });
    grouped.get(key).matches.push(match);
  }

  for (const [label, { pattern, matches }] of grouped) {
    const locations = matches.slice(0, 5).map(m => {
      const relPath = m.filePath.replace(backendRoot, 'backend');
      return `${relPath}:${m.lineNumber}`;
    }).join(', ');
    const extra = matches.length > 5 ? ` (+${matches.length - 5} more)` : '';
    findings.push({
      type: 'vulnerability',
      title: label,
      description: `Found at: ${locations}${extra}`,
      code_example: redact(matches[0].line),
      cve: null,
    });
  }

  // --- Layer 2: Analyze .env file ---
  const envPath = path.join(backendRoot, '.env');
  const envContent = await readFile(envPath);

  if (envContent) {
    const envLines = envContent.split('\n');
    const weakSecrets = [
      { key: 'JWT_SECRET', weakValues: ['dev-', 'test-', 'default-', 'secret', 'changeme', '123', 'example'], severity: 'critical' },
      { key: 'CORS_ORIGIN', weakValues: ['*'], severity: 'high' },
      { key: 'NODE_ENV', weakValues: ['development', 'dev'], severity: 'high' },
    ];

    for (const line of envLines) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const [rawKey, ...rest] = line.split('=');
      const key = rawKey?.trim();
      const val = rest.join('=').trim();

      for (const { key: targetKey, weakValues, severity } of weakSecrets) {
        if (key !== targetKey) continue;
        const isWeak = weakValues.some(w => val.toLowerCase().includes(w.toLowerCase()));
        if (isWeak) {
          findings.push({
            type: 'vulnerability',
            title: `${key} has a weak/development value in .env`,
            description: `${key}=[REDACTED] — the current value matches known weak/dev patterns. If this .env is used in production or staged environments, this represents a critical exposure.`,
            code_example: `${key}=[REDACTED]`,
            cve: null,
          });
        }
        // Special case: CORS_ORIGIN=* is always a finding regardless of "weakness"
        if (key === 'CORS_ORIGIN' && val === '*') {
          findings.push({
            type: 'vulnerability',
            title: 'CORS_ORIGIN is explicitly set to wildcard (*) in .env',
            description: 'The active .env configuration sets CORS to accept requests from any origin. This is only acceptable for fully public APIs with no authentication.',
            code_example: 'CORS_ORIGIN=*',
            cve: null,
          });
        }
      }
    }

    // Check .gitignore includes .env
    const gitignorePath = path.join(backendRoot, '.gitignore');
    const gitignore = await readFile(gitignorePath);
    if (gitignore && !gitignore.includes('.env')) {
      findings.push({
        type: 'vulnerability',
        title: '.env not listed in .gitignore',
        description: 'The backend .gitignore does not include .env. Real credentials could be committed to version control.',
        code_example: null,
        cve: null,
      });
    }

    _codeSnippets['backend/.env (sanitized)'] = envLines
      .filter(l => !l.includes('=') || l.startsWith('#') || l.trim() === '')
      .concat(envLines.filter(l => l.includes('=') && !l.startsWith('#')).map(l => {
        const [k] = l.split('=');
        return `${k}=[REDACTED]`;
      }))
      .join('\n');
  } else {
    findings.push({
      type: 'info',
      title: '.env file not found',
      description: `No .env file found at ${envPath}. Ensure environment variables are properly managed in your deployment.`,
      code_example: null,
      cve: null,
    });
  }

  if (recommendations.length === 0) {
    recommendations.push(
      'Never use fallback hardcoded secrets (|| \'default-secret\'). Fail startup if required env vars are missing.',
      'Use a secrets manager (AWS Secrets Manager, Vault, Doppler) in production.',
      'Rotate JWT_SECRET and all API keys if they have ever been set to weak/dev values.',
      'Add a startup validation that throws if JWT_SECRET is shorter than 32 characters or matches known weak patterns.',
    );
  }

  const criticalCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = criticalCount >= 3 ? 'critical' : criticalCount >= 1 ? 'high' : findings.length > 0 ? 'medium' : 'ok';
  const score = Math.max(0, 100 - criticalCount * 20 - findings.filter(f => f.type === 'warning').length * 5);

  return { id: 'secrets', name: 'Secrets & Leaks', severity, score, findings, recommendations, _codeSnippets };
}
