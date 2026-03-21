import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;

  // Find server entry file
  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'Server entry file not found', description: 'Could not read server entry to analyze Helmet/CORS/header configuration.', code_example: null, cve: null });
    return { id: 'headers', name: 'Headers & CORS', severity: 'medium', score: 50, findings, recommendations, _codeSnippets };
  }

  _codeSnippets['server.js'] = truncate(serverContent, 2000);

  // --- Helmet analysis ---
  if (!serverContent.includes('helmet')) {
    findings.push({
      type: 'vulnerability',
      title: 'Helmet.js not detected',
      description: 'No Helmet import or usage found in the server entry. HTTP security headers (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, etc.) are not being set.',
      code_example: null,
      cve: null,
    });
  } else {
    if (/crossOriginResourcePolicy.*cross-origin/i.test(serverContent)) {
      findings.push({
        type: 'warning',
        title: 'Cross-Origin-Resource-Policy set to "cross-origin" — CORP disabled',
        description: 'Helmet\'s crossOriginResourcePolicy is overridden to "cross-origin", which allows any site to embed your resources. Use "same-site" unless cross-origin embedding is explicitly required.',
        code_example: 'helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } })  // Weakens isolation',
        cve: null,
      });
    }

    if (!/contentSecurityPolicy\s*:/.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Content-Security-Policy uses Helmet defaults',
        description: 'No custom CSP is configured. For API-only backends, Helmet\'s default CSP may not be appropriate. Consider explicitly configuring or disabling it for pure API servers.',
        code_example: '// For API servers:\nhelmet({ contentSecurityPolicy: false })',
        cve: null,
      });
    }

    if (/hsts.*false/i.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'HSTS is explicitly disabled',
        description: 'Strict-Transport-Security header is turned off. Browsers will not enforce HTTPS-only connections, enabling downgrade attacks.',
        code_example: null,
        cve: null,
      });
    }

    // Permissions-Policy
    if (!/permissionsPolicy|featurePolicy/i.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Permissions-Policy header not configured',
        description: 'No Permissions-Policy (formerly Feature-Policy) configuration found. This header lets you control which browser APIs (camera, microphone, geolocation) the page can use, limiting the blast radius of XSS.',
        code_example: 'helmet({ permissionsPolicy: { policy: { camera: [], microphone: [], geolocation: [] } } })',
        cve: null,
      });
    }

    // Referrer-Policy
    if (!/referrerPolicy/i.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Referrer-Policy not explicitly configured',
        description: 'No referrerPolicy setting found in Helmet or manual headers. Without it, the browser may send the full URL (including path and query params containing tokens) as the Referer header to third parties.',
        code_example: 'helmet({ referrerPolicy: { policy: \'strict-origin-when-cross-origin\' } })',
        cve: null,
      });
    }
  }

  // --- X-Powered-By ---
  if (!/app\.disable\s*\(\s*['"`]x-powered-by['"`]\s*\)|hidePoweredBy/i.test(serverContent)) {
    findings.push({
      type: 'warning',
      title: 'X-Powered-By header not removed',
      description: 'Express sends X-Powered-By: Express by default, advertising the framework and version to attackers. Disable it with app.disable(\'x-powered-by\') or Helmet\'s hidePoweredBy option.',
      code_example: 'app.disable(\'x-powered-by\')',
      cve: null,
    });
  }

  // --- CORS analysis ---
  const corsMatch = serverContent.match(/origin\s*:\s*([^\n,}]+)/);
  if (corsMatch) {
    const originConfig = corsMatch[1].trim();
    if (originConfig.includes("'*'") || originConfig.includes('"*"')) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS is configured with wildcard origin (*)',
        description: 'CORS origin is set to "*". Any website can make cross-origin requests to your API from a user\'s browser.',
        code_example: 'cors({ origin: \'*\' })',
        cve: null,
      });
    }

    if (/CORS_ORIGIN.*\|\|.*\[.*\*/.test(serverContent) || /\|\|\s*\['?\*'?\]/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS defaults to wildcard when CORS_ORIGIN env var is unset',
        description: 'The CORS configuration falls back to ["*"] if CORS_ORIGIN is not set. In any environment where CORS_ORIGIN is missing, all origins are accepted.',
        code_example: 'const origins = process.env.CORS_ORIGIN?.split(",") || [\'*\']',
        cve: null,
      });
    }
  }

  if (serverContent.includes('credentials: true') && /origin.*\*/.test(serverContent)) {
    findings.push({
      type: 'vulnerability',
      title: 'credentials: true with wildcard origin',
      description: 'Using credentials: true with wildcard origin is invalid per CORS spec but indicates a misconfiguration that must be corrected.',
      code_example: 'cors({ origin: \'*\', credentials: true })',
      cve: null,
    });
  }

  // --- Cookie flags ---
  const cookieMatches = await grepFiles(src, [
    /res\.cookie\s*\(/,
    /Set-Cookie/i,
  ], { extensions: ['.js'], contextLines: 3 });

  for (const match of cookieMatches) {
    const context = match.line + match.context.after.join('\n');
    const missingHttpOnly = !/httpOnly\s*:\s*true/i.test(context);
    const missingSecure = !/secure\s*:\s*true/i.test(context);

    if (missingHttpOnly || missingSecure) {
      const missing = [missingHttpOnly && 'httpOnly', missingSecure && 'secure'].filter(Boolean).join(', ');
      findings.push({
        type: 'vulnerability',
        title: `Cookie set without ${missing} flag(s)`,
        description: `Found res.cookie() at ${path.basename(match.filePath)}:${match.lineNumber} missing ${missing}. Without httpOnly, JS can read the cookie (XSS risk). Without secure, cookie is sent over HTTP (MITM risk).`,
        code_example: `res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'strict' })`,
        cve: null,
      });
      break; // Report once
    }
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist in production. Never use * in production.',
    'Change crossOriginResourcePolicy back to "same-site" unless you have a specific cross-origin embedding requirement.',
    'Add app.disable(\'x-powered-by\') or use Helmet\'s hidePoweredBy to remove the Express fingerprint.',
    'Configure Permissions-Policy to restrict unused browser APIs.',
    'Set Referrer-Policy to strict-origin-when-cross-origin to prevent token leakage via Referer.',
    'Always set httpOnly: true and secure: true on all authentication cookies.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount >= 1 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 10);

  return { id: 'headers', name: 'Headers & CORS', severity, score, findings, recommendations, _codeSnippets };
}
