import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const middlewareDir = structure.dirs.middleware || path.join(src, 'middleware');

  // --- Find rate limiting configuration ---
  // Search middleware dir first, then entire src
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
      description: 'No rateLimit, rate-limit, throttle, or throttler pattern found in any source file. Without rate limiting, the API is vulnerable to brute force, credential stuffing, and denial of service attacks.',
      code_example: null,
      cve: null,
    });
  } else {
    // Try to read the rate limit file for deeper analysis
    const rateLimitFile = rateLimitMatches[0]?.filePath;
    const rateLimitContent = rateLimitFile ? await readFile(rateLimitFile) : null;

    if (rateLimitContent) {
      _codeSnippets[path.basename(rateLimitFile)] = truncate(rateLimitContent, 2000);

      // Parse rateLimit({ windowMs, max }) blocks
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
          description: 'All rate limiters use the default IP-based keying. Authenticated users can bypass limits by rotating IPs (e.g., via VPN). Add keyGenerator for authenticated routes to rate limit by userId.',
          code_example: 'keyGenerator: (req) => req.user?.id || req.ip',
          cve: null,
        });
      }

      if (!/standardHeaders.*true/i.test(rateLimitContent)) {
        findings.push({
          type: 'info',
          title: 'Some rate limiters may be missing standardHeaders: true',
          description: 'Without standardHeaders: true, clients cannot detect rate limit status from response headers (RateLimit-Remaining, RateLimit-Reset).',
          code_example: 'standardHeaders: true,\nlegacyHeaders: false,',
          cve: null,
        });
      }
    }

    // Check server applies rate limiter globally
    if (serverContent && !/apiLimiter|rateLimit/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'Rate limiter not applied globally in server entry',
        description: 'The rate limiter does not appear to be mounted globally. Routes without explicit limiters are unprotected.',
        code_example: 'app.use(apiLimiter)  // Mount globally before route definitions',
        cve: null,
      });
    }
  }

  // --- Slowloris / timeout configuration ---
  const timeoutMatches = await grepFiles(src, [
    /server\.timeout\s*=|keepAliveTimeout|headersTimeout/,
  ], { extensions: ['.js'] });

  if (timeoutMatches.length === 0 && serverContent && !/server\.timeout|keepAliveTimeout|headersTimeout/.test(serverContent)) {
    findings.push({
      type: 'warning',
      title: 'No server timeout configuration detected (Slowloris risk)',
      description: 'No server.timeout, keepAliveTimeout, or headersTimeout found. Without timeouts, a slow client (Slowloris attack) can hold connections open indefinitely, exhausting the server\'s connection pool.',
      code_example: 'server.keepAliveTimeout = 65000;\nserver.headersTimeout = 66000;',
      cve: null,
    });
  }

  // --- Compression bomb risk ---
  const compressionMatches = await grepFiles(src, [
    /compression\(\)/,
  ], { extensions: ['.js'] });

  if (compressionMatches.length > 0) {
    // Check if there is a Content-Length limit before compression
    const hasContentLengthLimit = serverContent
      ? /limit\s*:|content.?length/i.test(serverContent)
      : false;

    if (!hasContentLengthLimit) {
      findings.push({
        type: 'info',
        title: 'Compression enabled without explicit Content-Length limit',
        description: 'compression() middleware is active. Without a Content-Length or body-size limit before compression, a client can send a highly compressible payload (zip bomb) that decompresses to a large size, consuming server memory.',
        code_example: '// Add body limit before compression:\napp.use(express.json({ limit: \'1mb\' }))\napp.use(compression())',
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
    'Always set a request body size limit (express.json({ limit: \'1mb\' })) before mounting compression.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 10);

  return { id: 'ddos', name: 'DDoS & Rate Limiting', severity, score, findings, recommendations, _codeSnippets };
}
