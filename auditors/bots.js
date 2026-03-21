import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const routesDir = structure.dirs.routes || src;

  // --- CAPTCHA check ---
  const captchaMatches = await grepFiles(src, [
    /captcha|recaptcha|hcaptcha|turnstile|friendly.captcha/i,
  ], { extensions: ['.js'] });

  if (captchaMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No CAPTCHA or proof-of-work on registration and password reset',
      description: 'No CAPTCHA integration (reCAPTCHA, hCaptcha, Cloudflare Turnstile) found in any source file. Registration and password reset endpoints rely solely on rate limiting for bot protection, which can be bypassed with distributed IPs.',
      code_example: null,
      cve: null,
    });
  }

  // --- User-agent logging/filtering ---
  const uaMatches = await grepFiles(src, [
    /user.agent|userAgent|req\.headers\[['"`]user-agent['"`]\]/i,
  ], { extensions: ['.js'] });

  if (uaMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'User-Agent not logged or filtered',
      description: 'No User-Agent inspection found in middleware or controllers. Logging User-Agent helps identify bot patterns. Blocking known bad agents adds defense-in-depth.',
      code_example: null,
      cve: null,
    });
  }

  // --- Bot detection library ---
  const botLibMatches = await grepFiles(src, [
    /botd|express-bot-detection|isbot|@fingerprintjs/i,
  ], { extensions: ['.js'] });

  if (botLibMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No bot detection library detected',
      description: 'No bot detection library (isbot, botd, @fingerprintjs/botd) found. For endpoints serving public content or accepting registrations, lightweight bot scoring adds protection beyond rate limits.',
      code_example: null,
      cve: null,
    });
  }

  // --- Check sensitive endpoints for rate limiting ---
  const sensitivePatterns = ['/register', '/signup', '/forgot', '/reset'];
  const rateLimitPattern = /rateLimit|rate-limit|throttle|limiter/i;

  // Grep all route files for sensitive endpoint patterns
  const sensitiveRouteMatches = await grepFiles(routesDir, [
    /router\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]*(register|signup|forgot|reset)[^'"`]*['"`]/i,
  ], { extensions: ['.js'], contextLines: 5 });

  const unprotectedSensitive = sensitiveRouteMatches.filter(m => {
    const context = m.context.before.join('\n') + m.line + m.context.after.join('\n');
    return !rateLimitPattern.test(context);
  });

  if (unprotectedSensitive.length > 0) {
    const locs = unprotectedSensitive.slice(0, 5).map(m => {
      return `${path.basename(m.filePath)}:${m.lineNumber} (${m.line.match(/['"`]([^'"`]+)['"`]/)?.[1] || 'route'})`;
    }).join(', ');
    findings.push({
      type: 'warning',
      title: 'Registration/reset endpoints may lack rate limiting',
      description: `Found ${unprotectedSensitive.length} sensitive endpoint(s) without a visible rate limiter in context: ${locs}. These endpoints are prime targets for credential stuffing, account enumeration, and automated abuse.`,
      code_example: '// Add rate limiting:\nrouter.post(\'/register\', registerLimiter, registerController)',
      cve: null,
    });
  }

  // --- Login velocity detection ---
  const loginLogMatches = await grepFiles(src, [/LoginLog|loginLog|login_log/i], { extensions: ['.js'] });
  if (loginLogMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No login velocity/anomaly detection',
      description: 'No LoginLog analysis detected. Without tracking login attempts per user/IP over time, brute force campaigns that stay under per-request rate limits are not detected.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Add Cloudflare Turnstile (invisible CAPTCHA) to /register and /forgot-password endpoints.',
    'Log User-Agent for all auth events to aid bot pattern analysis.',
    'Add rate limiting to all registration, login, forgot-password, and reset-password endpoints.',
    'Use login velocity tracking to lock accounts after N failures per hour, independent of per-IP rate limits.',
  );

  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = warnCount >= 3 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - warnCount * 12);

  return { id: 'bots', name: 'Bots & Scraping', severity, score, findings, recommendations, _codeSnippets };
}
