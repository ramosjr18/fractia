import path from 'path';
import { readFile, grepFiles, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();

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
      description: 'No User-Agent inspection found in middleware or controllers. Logging User-Agent helps identify bot patterns in audit logs. Blocking known bad agents adds defense-in-depth.',
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

  // --- Check LinkedIn extension import endpoint rate limit ---
  const extensionRoutePath = path.join(src, 'routes', 'extension.routes.js');
  const extensionRoute = await readFile(extensionRoutePath);
  if (extensionRoute) {
    if (/extensionImportLimiter|rateLimit/i.test(extensionRoute)) {
      findings.push({
        type: 'info',
        title: 'Extension import endpoints have rate limiting (good)',
        description: 'The extension import routes use extensionImportLimiter. This protects against bulk scraping via the extension API.',
        code_example: null,
        cve: null,
      });
    } else {
      findings.push({
        type: 'warning',
        title: 'Extension import endpoint may lack rate limiting',
        description: 'The extension route file does not show clear rate limiting. If this endpoint accepts LinkedIn profile imports, it could be used for bulk scraping or data harvesting.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- Check for login velocity detection ---
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
    'Add Cloudflare Turnstile (invisible CAPTCHA) to /auth/register and /auth/forgot-password endpoints.',
    'Log User-Agent in the SecurityLogger for auth events to aid bot pattern analysis.',
    'Use the LoginLog model to implement login velocity checks: lock account after N failures per hour.',
    'For the extension import endpoint, consider requiring authenticated requests to be tied to a verified TOTP device.',
  );

  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = warnCount >= 3 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - warnCount * 12);

  return { id: 'bots', name: 'Bots & Scraping', severity, score, findings, recommendations, _codeSnippets };
}
