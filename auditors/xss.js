import path from 'path';
import { readFile, grepFiles, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const serverPath = path.join(src, 'server.js');
  const serverContent = await readFile(serverPath);

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'server.js not found', description: 'Cannot analyze CORS/XSS configuration.', code_example: null, cve: null });
    return { id: 'xss', name: 'XSS & CSRF', severity: 'medium', score: 50, findings, recommendations, _codeSnippets };
  }

  _codeSnippets['src/server.js (CORS)'] = truncate(serverContent, 1500);

  // --- CORS wildcard ---
  if (/CORS_ORIGIN.*\|\|.*\*|\['?\*'?\]/.test(serverContent)) {
    findings.push({
      type: 'vulnerability',
      title: 'CORS defaults to wildcard (*) when CORS_ORIGIN is unset',
      description: 'If CORS_ORIGIN env var is missing, all origins are accepted. This allows any website to make cross-origin requests to your API using a visitor\'s credentials.',
      code_example: '// server.js CORS origin callback falls back to [\'*\']',
      cve: null,
    });
  }

  // --- CSRF: check for CSRF token middleware on state-changing routes ---
  const hasCsrfMiddleware = /csrf|csurf|doubleCsrf/i.test(serverContent);
  if (!hasCsrfMiddleware) {
    // CSRF is less critical for JWT-based pure JSON APIs (no cookie auth)
    // But check if the app uses cookies for auth
    const usesCookies = /cookie-parser|req\.cookies|res\.cookie/i.test(serverContent);
    if (usesCookies) {
      findings.push({
        type: 'vulnerability',
        title: 'Cookie-based auth without CSRF protection',
        description: 'The app uses cookies but no CSRF middleware is detected. Cookie-authenticated requests are vulnerable to cross-site request forgery (CSRF) attacks from malicious websites.',
        code_example: null,
        cve: 'CWE-352',
      });
    } else {
      findings.push({
        type: 'info',
        title: 'No CSRF middleware (acceptable for JWT Bearer auth)',
        description: 'No CSRF protection found, but if authentication is purely via Authorization: Bearer headers (not cookies), CSRF is not a concern — browsers do not auto-send custom headers cross-origin.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- Check for res.send/res.json with req.body/req.params directly (potential XSS reflection) ---
  const reflectedInputMatches = await grepFiles(src, [
    /res\.(send|end)\s*\(.*req\.(body|params|query)/,
  ], { extensions: ['.js'] });

  if (reflectedInputMatches.length > 0) {
    const locations = reflectedInputMatches.slice(0, 3).map(m => {
      const relPath = m.filePath.replace(src, 'src');
      return `${relPath}:${m.lineNumber}`;
    }).join(', ');
    findings.push({
      type: 'warning',
      title: 'User input reflected directly in response',
      description: `Found res.send/end with req.body/params/query at: ${locations}. If Content-Type is text/html, this is a reflected XSS vector. JSON APIs are safe if Content-Type is application/json.`,
      code_example: reflectedInputMatches[0].line.trim(),
      cve: 'CWE-79',
    });
  }

  // --- Check for input sanitization middleware ---
  const hasSanitization = /sanitize|xss|DOMPurify|validator\.escape|express-validator/i.test(serverContent);
  if (!hasSanitization) {
    const controllerMatches = await grepFiles(path.join(src, 'controllers'), [
      /validator\.(escape|stripLow)|sanitize|xss/i,
    ], { extensions: ['.js'] });

    if (controllerMatches.length === 0) {
      findings.push({
        type: 'warning',
        title: 'No HTML/XSS sanitization detected in controllers',
        description: 'No use of validator.escape(), DOMPurify, or similar sanitization found in controllers. User-supplied strings stored and later rendered without sanitization could lead to stored XSS.',
        code_example: null,
        cve: 'CWE-79',
      });
    }
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist; never fallback to \'*\'.',
    'Ensure all API endpoints return Content-Type: application/json — this prevents reflection XSS even if input is echoed.',
    'Use express-validator\'s escape() on any user input that might be rendered in HTML (emails, PDFs, reports).',
    'If authentication ever moves to cookies, add csurf or double-submit cookie CSRF protection.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 8);

  return { id: 'xss', name: 'XSS & CSRF', severity, score, findings, recommendations, _codeSnippets };
}
