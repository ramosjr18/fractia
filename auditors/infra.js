import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const root = structure.files.packageJson ? path.dirname(structure.files.packageJson) : src;

  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;
  const errorsContent = await readFile(path.join(src, 'utils', 'errors.js'));
  const envContent = structure.files.env ? await readFile(structure.files.env) : null;

  if (serverContent) {
    _codeSnippets['server entry'] = truncate(serverContent, 1500);

    // 1. trust proxy
    const trustProxyMatch = serverContent.match(/trust\s*proxy['"]*\s*,\s*([^\n;)]+)/);
    if (trustProxyMatch) {
      const val = trustProxyMatch[1].trim();
      findings.push({
        type: 'info',
        title: `trust proxy set to ${val}`,
        description: `app.set('trust proxy', ${val}) trusts the first proxy in the chain. Correct for single reverse-proxy setups. If over-trusted, attackers can spoof X-Forwarded-For to bypass IP-based rate limiting.`,
        code_example: `app.set('trust proxy', ${val})`,
        cve: null,
      });
    } else if (!serverContent.includes('trust proxy')) {
      findings.push({
        type: 'warning',
        title: 'trust proxy not configured',
        description: 'If the app runs behind a reverse proxy (Nginx, AWS ALB, Cloudflare), not setting trust proxy means req.ip will always be the proxy\'s IP, breaking IP-based rate limiting.',
        code_example: null,
        cve: null,
      });
    }

    // 2. Body parser limit
    const bodyLimitMatch = serverContent.match(/express\.json\s*\(\s*\{[^}]*limit\s*:\s*['"`]([^'"`]+)['"`]/);
    if (bodyLimitMatch) {
      const limit = bodyLimitMatch[1];
      const mb = limit.includes('mb') ? parseInt(limit) : limit.includes('kb') ? parseInt(limit) / 1000 : 0;
      if (mb >= 5) {
        findings.push({
          type: 'warning',
          title: `JSON body parser limit is ${limit}`,
          description: `A ${limit} request body limit allows large payloads that can exhaust server memory. For most API endpoints, 1MB is sufficient.`,
          code_example: `express.json({ limit: '${limit}' })  // Consider '1mb' for API routes`,
          cve: null,
        });
      }
    }

    // 3. Error handler leaking stack traces
    if (errorsContent) {
      _codeSnippets['utils/errors.js'] = truncate(errorsContent, 1000);
      if (!/NODE_ENV.*production|process\.env\.NODE_ENV/.test(errorsContent) && /stack/i.test(errorsContent)) {
        findings.push({
          type: 'warning',
          title: 'Error handler may expose stack traces in all environments',
          description: 'The error handler includes stack trace data but may not gate it behind NODE_ENV !== production. Stack traces reveal file paths, line numbers, and dependency versions to attackers.',
          code_example: null,
          cve: null,
        });
      }
    }

    // 4. Env var validation at startup
    const hasEnvValidation = /if\s*\(\s*!process\.env\.|process\.env\.\w+\s*\|\|\s*.*throw/.test(serverContent);
    if (!hasEnvValidation) {
      findings.push({
        type: 'warning',
        title: 'No required environment variable validation at startup',
        description: 'No startup check found that throws if critical env vars (JWT_SECRET, DATABASE_URL, etc.) are missing. Missing vars cause silent fallbacks to insecure defaults or unpredictable failures in production.',
        code_example: 'if (!process.env.JWT_SECRET) throw new Error(\'JWT_SECRET is required\')',
        cve: null,
      });
    }
  }

  // 5. --inspect / --debug in package.json scripts
  const pkgPath = structure.files.packageJson || path.join(root, 'package.json');
  const pkgContent = await readFile(pkgPath);
  if (pkgContent) {
    try {
      const pkg = JSON.parse(pkgContent);
      const prodScripts = ['start', 'prod', 'serve', 'production'];
      for (const scriptName of prodScripts) {
        const scriptCmd = pkg.scripts?.[scriptName];
        if (scriptCmd && /--inspect|--debug-brk|--debug/.test(scriptCmd)) {
          findings.push({
            type: 'vulnerability',
            title: `--inspect / --debug flag in '${scriptName}' npm script`,
            description: `The "${scriptName}" script contains a Node.js debugger flag: "${scriptCmd}". If this script runs in production, it opens a remote debugging port that allows arbitrary code execution with the server's privileges.`,
            code_example: `"${scriptName}": "${scriptCmd}"`,
            cve: null,
          });
        }
      }
    } catch {}
  }

  // 6. console.log count in controllers/services
  const consoleDirs = [
    structure.dirs.controllers,
    structure.dirs.services,
  ].filter(Boolean);

  let totalConsoleLogs = 0;
  for (const dir of consoleDirs) {
    const matches = await grepFiles(dir, [/console\.log\s*\(/], { extensions: ['.js'] });
    totalConsoleLogs += matches.length;
  }

  if (totalConsoleLogs > 5) {
    findings.push({
      type: 'warning',
      title: `${totalConsoleLogs} console.log() calls found in controllers/services`,
      description: 'Excessive console.log usage in production code leaks internal details to server logs (including potentially sensitive request data), and cannot be disabled without code changes. Use a structured logger with log levels.',
      code_example: '// Replace console.log with a structured logger:\nlogger.debug(\'Processing request\', { userId, action })',
      cve: null,
    });
  }

  // 7. .env.example / .env.sample with real secrets
  const envExampleCandidates = ['.env.example', '.env.sample', '.env.template'];
  for (const exFile of envExampleCandidates) {
    const exPath = path.join(root, exFile);
    const exContent = await readFile(exPath);
    if (!exContent) continue;

    const lines = exContent.split('\n');
    const suspiciousLines = lines.filter(l => {
      if (!l.includes('=') || l.startsWith('#') || !l.trim()) return false;
      const [, val] = l.split('=');
      const v = (val || '').trim();
      if (v.length < 20) return false;
      const isPlaceholder = /your|example|change|xxx|placeholder|here|todo|fill/i.test(v);
      return !isPlaceholder;
    });

    if (suspiciousLines.length > 0) {
      findings.push({
        type: 'warning',
        title: `${exFile} may contain real secrets instead of placeholder values`,
        description: `Found ${suspiciousLines.length} value(s) in ${exFile} that appear to be real secrets (length > 20 chars, no placeholder language). Example files committed to VCS should only contain placeholder values like YOUR_KEY_HERE.`,
        code_example: null,
        cve: null,
      });
    }
  }

  // 8. NODE_ENV in .env
  if (envContent) {
    if (/NODE_ENV\s*=\s*(development|dev)\s/i.test(envContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'NODE_ENV=development in .env',
        description: 'The .env file has NODE_ENV=development. If deployed to staging or production, Express debugging is enabled, error details are verbose, and some security checks may be relaxed.',
        code_example: 'NODE_ENV=development  # Must be NODE_ENV=production in deployed environments',
        cve: null,
      });
    }

    const criticalVars = ['JWT_SECRET', 'DATABASE_URL'];
    for (const v of criticalVars) {
      if (!envContent.includes(v + '=')) {
        findings.push({
          type: 'warning',
          title: `${v} not found in .env`,
          description: `${v} is a required environment variable. If it falls back to a default, security may be compromised.`,
          code_example: null,
          cve: null,
        });
      }
    }
  }

  recommendations.push(
    'Set NODE_ENV=production in all deployed environments. Use separate .env files per environment.',
    'Add startup validation that throws if required env vars (JWT_SECRET, DATABASE_URL) are missing.',
    'Reduce JSON body limit to \'1mb\' for API routes.',
    'Ensure error handler returns stack traces only when NODE_ENV !== \'production\'.',
    'Remove --inspect and --debug-brk flags from all production npm scripts.',
    'Replace console.log in controllers/services with a structured logger (winston, pino).',
    'Ensure .env.example contains only placeholder values, never real keys.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 22 - warnCount * 8);

  return { id: 'infra', name: 'Infraestructura', severity, score, findings, recommendations, _codeSnippets };
}
