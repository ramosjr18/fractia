import path from 'path';
import { readFile, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const serverPath = path.join(src, 'server.js');
  const serverContent = await readFile(serverPath);

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'server.js not found', description: 'Could not read server.js to analyze Helmet configuration.', code_example: null, cve: null });
    return { id: 'headers', name: 'Headers & CORS', severity: 'medium', score: 50, findings, recommendations, _codeSnippets };
  }

  _codeSnippets['src/server.js'] = truncate(serverContent, 2000);

  // --- Helmet analysis ---
  if (!serverContent.includes('helmet')) {
    findings.push({
      type: 'vulnerability',
      title: 'Helmet.js not detected',
      description: 'No Helmet import or usage found in server.js. HTTP security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, etc.) are not being set.',
      code_example: null,
      cve: null,
    });
  } else {
    // Check CORP override
    if (/crossOriginResourcePolicy.*cross-origin/i.test(serverContent)) {
      findings.push({
        type: 'warning',
        title: 'Cross-Origin-Resource-Policy set to "cross-origin" — CORP disabled',
        description: 'Helmet\'s crossOriginResourcePolicy is overridden to "cross-origin", which allows any site to embed your resources (images, scripts, etc.). This disables CORP protection. Use "same-site" unless cross-origin embedding is explicitly required.',
        code_example: 'helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } })  // Weakens isolation',
        cve: null,
      });
    }

    // Check for explicit CSP configuration
    if (!/contentSecurityPolicy\s*:/.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Content-Security-Policy uses Helmet defaults',
        description: 'No custom CSP is configured. For an API-only backend, Helmet\'s default CSP may not be restrictive enough. Consider explicitly setting directives or disabling CSP for pure API servers where it adds no value.',
        code_example: '// For API servers:\nhelmet({ contentSecurityPolicy: false })\n// For frontends: configure strict CSP directives',
        cve: null,
      });
    }

    // Check HSTS
    if (/hsts.*false/i.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'HSTS is explicitly disabled',
        description: 'Strict-Transport-Security header is turned off. Browsers will not enforce HTTPS-only connections, enabling downgrade attacks.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- CORS analysis ---
  const corsMatch = serverContent.match(/origin\s*:\s*([^\n,}]+)/);
  if (corsMatch) {
    const originConfig = corsMatch[1].trim();
    if (originConfig.includes("'*'") || originConfig.includes('"*"')) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS is configured with wildcard origin (*)',
        description: 'CORS origin is set to "*". Combined with credentials: true (if present), this is especially dangerous. Any website can make credentialed requests to your API from a user\'s browser.',
        code_example: 'cors({ origin: \'*\' })',
        cve: null,
      });
    }

    // Check for unset CORS_ORIGIN fallback
    if (/CORS_ORIGIN.*\|\|.*\[.*\*/.test(serverContent) || /\|\|\s*\['?\*'?\]/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS defaults to wildcard when CORS_ORIGIN env var is unset',
        description: 'The CORS configuration falls back to ["*"] if CORS_ORIGIN is not set. In any environment where CORS_ORIGIN is missing from .env, all origins are accepted.',
        code_example: 'const origins = process.env.CORS_ORIGIN?.split(",") || [\'*\']',
        cve: null,
      });
    }
  }

  // Check credentials: true with wildcard (would be blocked by browser but still bad practice)
  if (serverContent.includes('credentials: true') && /origin.*\*/.test(serverContent)) {
    findings.push({
      type: 'vulnerability',
      title: 'credentials: true with wildcard origin',
      description: 'Using credentials: true together with a wildcard origin is invalid per the CORS spec (browsers will block it), but indicates a misconfiguration that needs to be corrected before any proper origin restriction is applied.',
      code_example: 'cors({ origin: \'*\', credentials: true })',
      cve: null,
    });
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist in production (e.g., https://app.yourdomain.com). Never use * in production.',
    'Change crossOriginResourcePolicy back to "same-site" or "same-origin" unless you have a specific cross-origin embedding requirement.',
    'Add a startup check: if CORS_ORIGIN is not set in production, throw an error.',
    'For API servers, consider: helmet({ contentSecurityPolicy: false }) and document the decision.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount >= 1 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 10);

  return { id: 'headers', name: 'Headers & CORS', severity, score, findings, recommendations, _codeSnippets };
}
