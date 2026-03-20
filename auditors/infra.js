import path from 'path';
import { readFile, BACKEND_SRC, BACKEND_ROOT, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const root = BACKEND_ROOT();

  const serverContent  = await readFile(path.join(src, 'server.js'));
  const errorsContent  = await readFile(path.join(src, 'utils', 'errors.js'));
  const envContent     = await readFile(path.join(root, '.env'));

  if (serverContent) {
    _codeSnippets['src/server.js'] = truncate(serverContent, 1500);

    // 1. trust proxy
    const trustProxyMatch = serverContent.match(/trust\s*proxy['"]*\s*,\s*([^\n;)]+)/);
    if (trustProxyMatch) {
      const val = trustProxyMatch[1].trim();
      findings.push({
        type: 'info',
        title: `trust proxy set to ${val}`,
        description: `app.set('trust proxy', ${val}) trusts the first proxy in the chain. Correct for single reverse-proxy setups (Nginx, Cloudflare). If over-trusted, attackers can spoof X-Forwarded-For to bypass IP-based rate limiting. Verify this matches your exact deployment topology.`,
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
          description: `A ${limit} request body limit allows large payloads that can exhaust server memory. For most API endpoints, 1MB is sufficient. Only file upload endpoints need higher limits.`,
          code_example: `express.json({ limit: '${limit}' })  // Consider '1mb' for API routes`,
          cve: null,
        });
      }
    }

    // 3. Check for express error handler leaking stack traces
    if (errorsContent) {
      _codeSnippets['utils/errors.js'] = truncate(errorsContent, 1000);
      if (!/NODE_ENV.*production|process\.env\.NODE_ENV/.test(errorsContent) && /stack/i.test(errorsContent)) {
        findings.push({
          type: 'warning',
          title: 'Error handler may expose stack traces in all environments',
          description: 'The error handler includes stack trace data but may not gate it behind NODE_ENV !== production check. Stack traces reveal file paths, line numbers, and dependency versions to attackers.',
          code_example: null,
          cve: null,
        });
      }
    }
  }

  // 4. NODE_ENV in .env
  if (envContent) {
    if (/NODE_ENV\s*=\s*(development|dev)\s/i.test(envContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'NODE_ENV=development in .env',
        description: 'The .env file has NODE_ENV=development. If this .env is deployed to a staging or production server, Express debugging features are enabled, error details are more verbose, and some security checks may be relaxed.',
        code_example: 'NODE_ENV=development  # Must be NODE_ENV=production in deployed environments',
        cve: null,
      });
    }

    // Check for missing critical env vars
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
    'Add startup validation that throws if required env vars (JWT_SECRET, DATABASE_URL) are missing or use known weak defaults.',
    'Reduce JSON body limit to \'1mb\' for API routes; use the existing upload middleware for file endpoints.',
    'Ensure error handler returns stack traces only when NODE_ENV !== \'production\'.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 22 - warnCount * 8);

  return { id: 'infra', name: 'Infraestructura', severity, score, findings, recommendations, _codeSnippets };
}
