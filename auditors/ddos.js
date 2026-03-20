import path from 'path';
import { readFile, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const rateLimitPath = path.join(src, 'middleware', 'rateLimit.js');
  const serverPath    = path.join(src, 'server.js');

  const rateLimitContent = await readFile(rateLimitPath);
  const serverContent    = await readFile(serverPath);

  if (!rateLimitContent) {
    findings.push({ type: 'warning', title: 'rateLimit.js not found', description: 'Could not find rate limit middleware.', code_example: null, cve: null });
    return { id: 'ddos', name: 'DDoS & Rate Limiting', severity: 'high', score: 40, findings, recommendations, _codeSnippets };
  }

  _codeSnippets['middleware/rateLimit.js'] = truncate(rateLimitContent, 2000);

  // Parse all rateLimit({ windowMs, max }) blocks
  const blocks = [];
  const blockRegex = /const\s+(\w+)\s*=\s*rateLimit\(\s*\{([^}]+)\}/gs;
  let m;
  while ((m = blockRegex.exec(rateLimitContent)) !== null) {
    const name = m[1];
    const body = m[2];
    const windowMatch = body.match(/windowMs\s*:\s*([\d_*\s]+)/);
    const maxMatch    = body.match(/max\s*:\s*([\d_]+|process\.env\.[A-Z_]+\s*\?\?\s*[\d_]+|parseInt\(process\.env\.[A-Z_]+\)[^,\n]*(?:\|\|\s*[\d_]+)?)/);
    const windowMs = windowMatch ? eval(windowMatch[1].replace(/_/g, '').trim()) : null;
    const maxRaw   = maxMatch ? maxMatch[1].trim() : null;
    // Resolve max: if it references env, extract fallback number
    let max = null;
    if (maxRaw) {
      const numMatch = maxRaw.match(/(\d+)\s*$/);
      if (numMatch) max = parseInt(numMatch[1]);
    }
    if (windowMs && max) blocks.push({ name, windowMs, max, ratePerSec: (max / (windowMs / 1000)).toFixed(3) });
  }

  // Flag overly generous limits
  for (const block of blocks) {
    const rps = parseFloat(block.ratePerSec);
    if (block.name === 'apiLimiter' && rps > 5) {
      findings.push({
        type: 'warning',
        title: `apiLimiter is generous: ${block.max} req/${block.windowMs / 60000}min (${rps} req/sec per IP)`,
        description: 'The general API rate limit allows high throughput per IP. A determined attacker or bot can make substantial requests before hitting the limit. Consider tighter limits for unauthenticated paths.',
        code_example: `windowMs: ${block.windowMs / 60000} * 60 * 1000,\nmax: ${block.max}`,
        cve: null,
      });
    }
  }

  // Check if rate limiters are IP-only (no userId-based keying)
  if (!/keyGenerator/i.test(rateLimitContent)) {
    findings.push({
      type: 'warning',
      title: 'Rate limiters are IP-based only — no per-user rate limiting',
      description: 'All rate limiters use the default IP-based keying. Authenticated users can bypass limits by rotating IPs (e.g., via VPN). Add keyGenerator for authenticated routes to rate limit by userId.',
      code_example: '// Add to authenticated limiters:\nkeyGenerator: (req) => req.user?.id || req.ip',
      cve: null,
    });
  }

  // Check standardHeaders on all limiters
  if (!/standardHeaders.*true/i.test(rateLimitContent)) {
    findings.push({
      type: 'info',
      title: 'Some rate limiters may be missing standardHeaders: true',
      description: 'Without standardHeaders: true, clients cannot detect rate limit status from response headers (RateLimit-Remaining, RateLimit-Reset), leading to unnecessary 429 retries.',
      code_example: '// Add to all limiters:\nstandardHeaders: true,\nlegacyHeaders: false,',
      cve: null,
    });
  }

  // Check server.js applies apiLimiter globally
  if (serverContent) {
    if (!serverContent.includes('apiLimiter') && !serverContent.includes('rateLimit')) {
      findings.push({
        type: 'vulnerability',
        title: 'apiLimiter not applied globally in server.js',
        description: 'The rate limiter does not appear to be mounted globally. Routes without explicit limiters are unprotected.',
        code_example: null,
        cve: null,
      });
    }
  }

  recommendations.push(
    'Add userId-based keyGenerator to authenticated route limiters to prevent IP-rotation bypass.',
    'Consider reducing apiLimiter to 30-50 req/15min for unauthenticated paths.',
    'Add standardHeaders: true, legacyHeaders: false to all rate limit configs.',
    'Use a distributed rate limiter (express-rate-limit + Redis store) so limits work correctly across multiple server instances.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 10);

  return { id: 'ddos', name: 'DDoS & Rate Limiting', severity, score, findings, recommendations, _codeSnippets };
}
