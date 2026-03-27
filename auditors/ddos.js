import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

// ─── Python / FastAPI pattern detection ──────────────────────────────────────

async function auditPython(src, structure) {
  const findings = [];
  const recommendations = [];

  // Detect Python files to scan
  const pyExtensions = ['.py'];

  // 1. Rate limiting — slowapi, limits, fastapi-limiter, starlette-limiter
  const rateLimitPatterns = [
    /slowapi|Limiter\s*\(|@limiter\.limit|RateLimiter|fastapi.?limiter|starlette.?limiter|limits\.storage/i,
  ];
  const rateLimitMatches = await grepFiles(src, rateLimitPatterns, { extensions: pyExtensions });

  if (rateLimitMatches.length === 0) {
    findings.push({
      type: 'vulnerability',
      title: 'No rate limiting middleware detected (Python/FastAPI)',
      description:
        'No slowapi, fastapi-limiter, or equivalent rate limiting library found in any Python source file. ' +
        'Without rate limiting, the API is vulnerable to brute force, credential stuffing, and denial of service attacks.',
      code_example:
        '# Install: pip install slowapi limits\n' +
        'from slowapi import Limiter\n' +
        'from slowapi.util import get_remote_address\n\n' +
        'limiter = Limiter(key_func=get_remote_address)\n' +
        'app.state.limiter = limiter\n\n' +
        '@app.get("/api/resource")\n' +
        '@limiter.limit("60/minute")\nasync def resource(request: Request): ...',
      cve: null,
    });
  } else {
    // Deeper analysis: read matched files to check for auth-based key generator
    const uniqueFiles = [...new Set(rateLimitMatches.map(m => m.filePath).filter(Boolean))];
    const allLimiterContent = (
      await Promise.all(uniqueFiles.map(f => readFile(f).catch(() => '')))
    ).join('\n');

    const hasAuthKey = /key_func.*token|key_func.*user|key_func.*auth|_auth_or_ip|bearer|Authorization/i.test(allLimiterContent);
    if (!hasAuthKey) {
      findings.push({
        type: 'warning',
        title: 'Rate limiter uses IP-based key only — no per-user keying detected',
        description:
          'Authenticated users can bypass IP-based rate limits by rotating IPs (VPN/proxy). ' +
          'Implement a key_func that extracts the Bearer token or user ID for authenticated routes.',
        code_example:
          'def _auth_or_ip_key(request: Request) -> str:\n' +
          '    auth = request.headers.get("Authorization", "")\n' +
          '    if auth.startswith("Bearer "):\n' +
          '        import hashlib\n' +
          '        return hashlib.sha256(auth[7:].encode()).hexdigest()[:16]\n' +
          '    return request.client.host\n\n' +
          'limiter = Limiter(key_func=_auth_or_ip_key)',
        cve: null,
      });
    }
  }

  // 2. Slowloris — timeout_keep_alive, timeout in uvicorn/gunicorn config
  const timeoutPatterns = [/timeout_keep_alive|keepalive_timeout|timeout\s*=\s*\d+|worker_timeout/i];
  const timeoutMatches = await grepFiles(src, timeoutPatterns, { extensions: pyExtensions });

  if (timeoutMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No server timeout configuration detected (Slowloris risk)',
      description:
        'No timeout_keep_alive, keepalive_timeout, or worker_timeout found. ' +
        'Without connection timeouts, a slow client (Slowloris attack) can hold connections open indefinitely.',
      code_example:
        '# uvicorn startup\nuvicorn.run(app, host="0.0.0.0", port=8000,\n    timeout_keep_alive=65,\n    timeout_graceful_shutdown=30)',
      cve: null,
    });
  }

  // 3. Body size limit — ContentSizeLimitMiddleware, MAX_CONTENT_LENGTH, body size checks
  const bodySizePatterns = [/ContentSizeLimitMiddleware|MAX_CONTENT_LENGTH|max_upload_size|content.?length.*limit|body.*limit/i];
  const bodySizeMatches = await grepFiles(src, bodySizePatterns, { extensions: pyExtensions });

  if (bodySizeMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No explicit request body size limit detected',
      description:
        'Without a body size limit, a client can upload arbitrarily large payloads, leading to memory exhaustion. ' +
        'Add ContentSizeLimitMiddleware or equivalent.',
      code_example:
        'from starlette.middleware.base import BaseHTTPMiddleware\n\n' +
        'class ContentSizeLimitMiddleware(BaseHTTPMiddleware):\n' +
        '    def __init__(self, app, max_bytes: int = 5 * 1024 * 1024):\n' +
        '        super().__init__(app)\n' +
        '        self.max_bytes = max_bytes\n' +
        '    async def dispatch(self, request, call_next):\n' +
        '        cl = request.headers.get("content-length")\n' +
        '        if cl and int(cl) > self.max_bytes:\n' +
        '            return Response("Payload too large", status_code=413)\n' +
        '        return await call_next(request)\n\n' +
        'app.add_middleware(ContentSizeLimitMiddleware, max_bytes=5*1024*1024)',
      cve: null,
    });
  }

  // 4. Security headers — X-Content-Type-Options, HSTS, X-Frame-Options
  const headersPatterns = [/X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options|SecurityHeadersMiddleware|secure_headers/i];
  const headersMatches = await grepFiles(src, headersPatterns, { extensions: pyExtensions });

  if (headersMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No security headers middleware detected',
      description:
        'Security response headers (HSTS, X-Content-Type-Options, X-Frame-Options) protect against a range of client-side attacks. ' +
        'Consider adding secure_headers or a custom middleware.',
      code_example:
        '# pip install secure\nimport secure\n\n' +
        'secure_headers = secure.Secure()\n\n' +
        '@app.middleware("http")\nasync def set_secure_headers(request, call_next):\n' +
        '    response = await call_next(request)\n' +
        '    secure_headers.framework.fastapi(response)\n' +
        '    return response',
      cve: null,
    });
  }

  recommendations.push(
    'Usa slowapi con key_func basado en Bearer token para rate limiting por usuario (no solo por IP).',
    'Configura timeout_keep_alive=65 en el arranque de Uvicorn para mitigar ataques Slowloris.',
    'Añade ContentSizeLimitMiddleware con límite de 5MB antes de procesar el body.',
    'Implementa security headers (HSTS, X-Content-Type-Options, X-Frame-Options) con el paquete `secure`.',
    'Considera Redis como backend de slowapi para rate limiting distribuido en múltiples workers.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 10);

  return { id: 'ddos', name: 'DDoS & Rate Limiting', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express pattern detection (original logic) ────────────────────

async function auditNode(src, structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const middlewareDir = structure.dirs.middleware || path.join(src, 'middleware');

  const rateLimitMatches = await grepFiles(middlewareDir, [
    /rateLimit|rate-limit|throttle|throttler/i,
  ], { extensions: ['.js'] });

  const rateLimitInSrc = rateLimitMatches.length === 0
    ? await grepFiles(src, [/rateLimit|rate-limit|throttle|throttler/i], { extensions: ['.js'] })
    : rateLimitMatches;

  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;

  if (rateLimitInSrc.length === 0) {
    findings.push({
      type: 'vulnerability',
      title: 'No rate limiting middleware detected',
      description:
        'No rateLimit, rate-limit, throttle, or throttler pattern found in any source file. ' +
        'Without rate limiting, the API is vulnerable to brute force, credential stuffing, and denial of service attacks.',
      code_example: null,
      cve: null,
    });
  } else {
    const rateLimitFile = rateLimitMatches[0]?.filePath;
    const rateLimitContent = rateLimitFile ? await readFile(rateLimitFile) : null;

    if (rateLimitContent) {
      _codeSnippets[path.basename(rateLimitFile)] = truncate(rateLimitContent, 2000);

      const blocks = [];
      const blockRegex = /const\s+(\w+)\s*=\s*rateLimit\(\s*\{([^}]+)\}/gs;
      let m;
      while ((m = blockRegex.exec(rateLimitContent)) !== null) {
        const name = m[1];
        const body = m[2];
        const windowMatch = body.match(/windowMs\s*:\s*([\d_*\s]+)/);
        const maxMatch = body.match(/max\s*:\s*([\d_]+|process\.env\.[A-Z_]+\s*\?\?\s*[\d_]+|parseInt\(process\.env\.[A-Z_]+\)[^,\n]*(?:\|\|\s*[\d_]+)?)/);
        const windowMs = windowMatch ? eval(windowMatch[1].replace(/_/g, '').trim()) : null;
        const maxRaw = maxMatch ? maxMatch[1].trim() : null;
        let max = null;
        if (maxRaw) {
          const numMatch = maxRaw.match(/(\d+)\s*$/);
          if (numMatch) max = parseInt(numMatch[1]);
        }
        if (windowMs && max) blocks.push({ name, windowMs, max, ratePerSec: (max / (windowMs / 1000)).toFixed(3) });
      }

      for (const block of blocks) {
        const rps = parseFloat(block.ratePerSec);
        if (block.name === 'apiLimiter' && rps > 5) {
          findings.push({
            type: 'warning',
            title: `apiLimiter is generous: ${block.max} req/${block.windowMs / 60000}min (${rps} req/sec per IP)`,
            description: 'The general API rate limit allows high throughput per IP. Consider tighter limits for unauthenticated paths.',
            code_example: `windowMs: ${block.windowMs / 60000} * 60 * 1000,\nmax: ${block.max}`,
            cve: null,
          });
        }
      }

      if (!/keyGenerator/i.test(rateLimitContent)) {
        findings.push({
          type: 'warning',
          title: 'Rate limiters are IP-based only — no per-user rate limiting',
          description:
            'All rate limiters use the default IP-based keying. Authenticated users can bypass limits by rotating IPs (e.g., via VPN). ' +
            'Add keyGenerator for authenticated routes to rate limit by userId.',
          code_example: 'keyGenerator: (req) => req.user?.id || req.ip',
          cve: null,
        });
      }

      if (!/standardHeaders.*true/i.test(rateLimitContent)) {
        findings.push({
          type: 'info',
          title: 'Some rate limiters may be missing standardHeaders: true',
          description:
            'Without standardHeaders: true, clients cannot detect rate limit status from response headers ' +
            '(RateLimit-Remaining, RateLimit-Reset).',
          code_example: 'standardHeaders: true,\nlegacyHeaders: false,',
          cve: null,
        });
      }
    }

    if (serverContent && !/apiLimiter|rateLimit/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'Rate limiter not applied globally in server entry',
        description:
          'The rate limiter does not appear to be mounted globally. Routes without explicit limiters are unprotected.',
        code_example: 'app.use(apiLimiter)  // Mount globally before route definitions',
        cve: null,
      });
    }
  }

  // Slowloris
  const timeoutMatches = await grepFiles(src, [
    /server\.timeout\s*=|keepAliveTimeout|headersTimeout/,
  ], { extensions: ['.js'] });

  if (timeoutMatches.length === 0 && serverContent && !/server\.timeout|keepAliveTimeout|headersTimeout/.test(serverContent)) {
    findings.push({
      type: 'warning',
      title: 'No server timeout configuration detected (Slowloris risk)',
      description:
        "No server.timeout, keepAliveTimeout, or headersTimeout found. Without timeouts, a slow client (Slowloris attack) can hold connections open indefinitely.",
      code_example: 'server.keepAliveTimeout = 65000;\nserver.headersTimeout = 66000;',
      cve: null,
    });
  }

  // Compression bomb
  const compressionMatches = await grepFiles(src, [/compression\(\)/], { extensions: ['.js'] });

  if (compressionMatches.length > 0) {
    const hasContentLengthLimit = serverContent
      ? /limit\s*:|content.?length/i.test(serverContent)
      : false;

    if (!hasContentLengthLimit) {
      findings.push({
        type: 'info',
        title: 'Compression enabled without explicit Content-Length limit',
        description:
          'compression() middleware is active. Without a Content-Length or body-size limit before compression, ' +
          'a client can send a highly compressible payload (zip bomb) that decompresses to a large size, consuming server memory.',
        code_example:
          "// Add body limit before compression:\napp.use(express.json({ limit: '1mb' }))\napp.use(compression())",
        cve: null,
      });
    }
  }

  recommendations.push(
    'Add userId-based keyGenerator to authenticated route limiters to prevent IP-rotation bypass.',
    'Consider reducing the general API limiter to 30-60 req/15min for unauthenticated paths.',
    'Add standardHeaders: true, legacyHeaders: false to all rate limit configs.',
    'Use a distributed rate limiter (express-rate-limit + Redis store) across multiple server instances.',
    'Set server.keepAliveTimeout = 65000 and server.headersTimeout = 66000 to mitigate Slowloris attacks.',
    "Always set a request body size limit (express.json({ limit: '1mb' })) before mounting compression.",
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 10);

  return { id: 'ddos', name: 'DDoS & Rate Limiting', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function audit(depth) {
  const structure = await discoverStructure();
  const src = structure.srcDir;

  // Detect if this is a Python project
  const isPython =
    structure.framework === 'unknown' &&
    !structure.files.packageJson &&
    structure.files.entryFile === null;

  // Check for requirements.txt as a stronger Python signal
  const { config } = await import('../config.js');
  const reqFile = path.join(config.projectRoot, 'requirements.txt');
  const mainFile = path.join(config.projectRoot, 'backend', 'requirements.txt');
  let hasPythonMarker = false;
  try {
    const { default: fs } = await import('fs/promises');
    await fs.access(reqFile).then(() => { hasPythonMarker = true; }).catch(() => {});
    if (!hasPythonMarker) {
      await fs.access(mainFile).then(() => { hasPythonMarker = true; }).catch(() => {});
    }
  } catch (_) { /* ignore */ }

  if (isPython || hasPythonMarker) {
    return auditPython(src, structure);
  }

  return auditNode(src, structure);
}
