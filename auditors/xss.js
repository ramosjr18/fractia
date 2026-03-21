import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');

  // Find server entry file (server.js / app.js / index.js)
  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'Server entry file not found', description: 'Cannot analyze CORS/XSS configuration.', code_example: null, cve: null });
  } else {
    _codeSnippets['server (CORS)'] = truncate(serverContent, 1500);

    // --- CORS wildcard ---
    if (/CORS_ORIGIN.*\|\|.*\*|\['?\*'?\]/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS defaults to wildcard (*) when CORS_ORIGIN is unset',
        description: 'If CORS_ORIGIN env var is missing, all origins are accepted. This allows any website to make cross-origin requests to your API using a visitor\'s credentials.',
        code_example: '// server CORS origin callback falls back to [\'*\']',
        cve: null,
      });
    }

    // --- CSRF ---
    const hasCsrfMiddleware = /csrf|csurf|doubleCsrf/i.test(serverContent);
    if (!hasCsrfMiddleware) {
      const usesCookies = /cookie-parser|req\.cookies|res\.cookie/i.test(serverContent);
      if (usesCookies) {
        findings.push({
          type: 'vulnerability',
          title: 'Cookie-based auth without CSRF protection',
          description: 'The app uses cookies but no CSRF middleware is detected. Cookie-authenticated requests are vulnerable to cross-site request forgery (CSRF) attacks.',
          code_example: null,
          cve: 'CWE-352',
        });
      } else {
        findings.push({
          type: 'info',
          title: 'No CSRF middleware (acceptable for JWT Bearer auth)',
          description: 'No CSRF protection found. If authentication is purely via Authorization: Bearer headers (not cookies), CSRF is not a concern.',
          code_example: null,
          cve: null,
        });
      }
    }

    // --- Input sanitization ---
    const hasSanitization = /sanitize|xss|DOMPurify|validator\.escape|express-validator/i.test(serverContent);
    if (!hasSanitization) {
      const controllerMatches = await grepFiles(controllersDir, [
        /validator\.(escape|stripLow)|sanitize|xss/i,
      ], { extensions: ['.js'] });

      if (controllerMatches.length === 0) {
        findings.push({
          type: 'warning',
          title: 'No HTML/XSS sanitization detected in controllers',
          description: 'No use of validator.escape(), DOMPurify, or similar sanitization found. User-supplied strings stored and later rendered without sanitization could lead to stored XSS.',
          code_example: null,
          cve: 'CWE-79',
        });
      }
    }
  }

  // --- User input reflected directly in response ---
  const reflectedInputMatches = await grepFiles(src, [
    /res\.(send|end)\s*\(.*req\.(body|params|query)/,
  ], { extensions: ['.js'] });

  if (reflectedInputMatches.length > 0) {
    const locations = reflectedInputMatches.slice(0, 3).map(m => {
      return `${m.filePath.replace(src, 'src')}:${m.lineNumber}`;
    }).join(', ');
    findings.push({
      type: 'warning',
      title: 'User input reflected directly in response',
      description: `Found res.send/end with req.body/params/query at: ${locations}. If Content-Type is text/html, this is a reflected XSS vector.`,
      code_example: reflectedInputMatches[0].line.trim(),
      cve: 'CWE-79',
    });
  }

  // --- Server-Side Template Injection (SSTI) ---
  const sstiMatches = await grepFiles(src, [
    /res\.render\s*\([^,]+,\s*\{[^}]*req\.(body|query|params)/,
    /ejs\.render\s*\(.*req\./,
    /handlebars\.compile\s*\(.*req\./,
    /pug\.render\s*\(.*req\./,
  ], { extensions: ['.js'] });

  if (sstiMatches.length > 0) {
    const locs = sstiMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Server-Side Template Injection (SSTI) risk',
      description: `Found template rendering with user-controlled data at: ${locs}. Passing req.body/query/params directly into a template engine can allow arbitrary code execution if the template engine evaluates expressions.`,
      code_example: sstiMatches[0]?.line.trim() || null,
      cve: 'CWE-94',
    });
  }

  // --- innerHTML / document.write with server data (frontend files) ---
  const domXssMatches = await grepFiles(src, [
    /innerHTML\s*=.*\+/,
    /document\.write\s*\(/,
    /eval\s*\(\s*.*req\.|eval\s*\(\s*.*data\./,
  ], { extensions: ['.js', '.html'] });

  if (domXssMatches.length > 0) {
    const locs = domXssMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'DOM-based XSS risk: innerHTML or document.write with dynamic data',
      description: `Found potentially dangerous DOM manipulation at: ${locs}. Using innerHTML with concatenated strings or document.write() with external data allows script injection without sanitization.`,
      code_example: domXssMatches[0]?.line.trim() || null,
      cve: 'CWE-79',
    });
  }

  // --- eval() in backend ---
  const evalMatches = await grepFiles(src, [
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /vm\.runInThisContext/,
  ], { extensions: ['.js'] });

  const evalFiltered = evalMatches.filter(m => {
    // Exclude comments and test files
    if (m.line.trim().startsWith('//') || m.line.trim().startsWith('*')) return false;
    if (m.filePath.includes('.test.') || m.filePath.includes('.spec.') || m.filePath.includes('node_modules')) return false;
    return true;
  });

  if (evalFiltered.length > 0) {
    const locs = evalFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'eval() or new Function() detected in backend source',
      description: `Found dynamic code execution at: ${locs}. eval(), new Function(), and vm.runInThisContext() execute arbitrary strings as code. If user input reaches these calls, it results in Remote Code Execution (RCE).`,
      code_example: evalFiltered[0]?.line.trim() || null,
      cve: null,
    });
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist; never fallback to \'*\'.',
    'Ensure all API endpoints return Content-Type: application/json — this prevents reflection XSS even if input is echoed.',
    'Use express-validator\'s escape() on any user input that might be rendered in HTML.',
    'Never pass req.body/query/params directly to template engines (res.render). Always extract and validate specific fields.',
    'Replace eval() and new Function() with safe alternatives. Use JSON.parse() for data, not eval().',
    'If authentication ever moves to cookies, add csurf or double-submit cookie CSRF protection.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 8);

  return { id: 'xss', name: 'XSS & CSRF', severity, score, findings, recommendations, _codeSnippets };
}
