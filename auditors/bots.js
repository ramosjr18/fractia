import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI bot protection audit ───────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. CAPTCHA
  const captchaMatches = await grepFiles(src, [
    /captcha|recaptcha|hcaptcha|turnstile|friendly.captcha/i,
  ], { extensions: py });

  if (captchaMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detectó CAPTCHA en endpoints de registro/reset',
      description:
        'No se encontró integración de reCAPTCHA, hCaptcha ni Cloudflare Turnstile. Los endpoints de registro y recuperación de contraseña dependen solo del rate limiting para protección frente a bots, lo que puede ser bypasseado con IPs distribuidas.',
      code_example:
        '# Verificación de Cloudflare Turnstile en FastAPI:\nimport httpx\n\n' +
        'async def verify_turnstile(token: str) -> bool:\n' +
        '    async with httpx.AsyncClient() as client:\n' +
        '        r = await client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify",\n' +
        '            data={"secret": TURNSTILE_SECRET, "response": token})\n' +
        '    return r.json().get("success", False)',
      cve: null,
    });
  }

  // 2. User-Agent inspection
  const uaMatches = await grepFiles(src, [
    /user.agent|user_agent|request\.headers\.get.*user.agent/i,
  ], { extensions: py });

  if (uaMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'User-Agent no logueado ni filtrado',
      description:
        'No se encontró inspección del User-Agent en middleware ni en los endpoints. Loguear el User-Agent ayuda a identificar patrones de bots. Bloquear agentes conocidos como maliciosos añade defensa en profundidad.',
      code_example:
        '@app.middleware("http")\nasync def log_user_agent(request: Request, call_next):\n' +
        '    ua = request.headers.get("user-agent", "")\n' +
        '    logger.info("Request", user_agent=ua, path=request.url.path)\n' +
        '    return await call_next(request)',
      cve: null,
    });
  }

  // 3. Bot detection library
  const botLibMatches = await grepFiles(src, [
    /isbot|user_agents|python.user.agents|botdetection/i,
  ], { extensions: py });

  if (botLibMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No se detectó librería de detección de bots',
      description:
        'No se encontró isbot ni user_agents (Python). Para endpoints públicos o de registro, la detección de bots añade protección más allá del rate limiting.',
      code_example:
        '# pip install user-agents\nfrom user_agents import parse\n\n' +
        'ua_string = request.headers.get("user-agent", "")\nua = parse(ua_string)\nif ua.is_bot:\n    raise HTTPException(403, "Bot detectado")',
      cve: null,
    });
  }

  // 4. Login velocity / anomaly detection
  const velocityMatches = await grepFiles(src, [
    /failed_attempts|login_attempts|login_log|LoginLog|velocity/i,
  ], { extensions: py });

  if (velocityMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detecta seguimiento de velocidad de login / anomalías',
      description:
        'Sin seguimiento de intentos de login por usuario/IP a lo largo del tiempo, los ataques de fuerza bruta distribuidos que se mantienen bajo el rate limit por petición no son detectados.',
      code_example:
        '# En Redis:\nkey = f"login_attempts:{user_email}"\nattempts = await redis.incr(key)\nif attempts == 1:\n    await redis.expire(key, 3600)  # 1 hora\nif attempts > 10:\n    raise HTTPException(429, "Demasiados intentos fallidos")',
      cve: null,
    });
  }

  // 5. Sensitive Python endpoints with rate limiting
  const routeMatches = await grepFiles(src, [
    /@\w+\.(post|get|put|delete|patch)\s*\(\s*["'].*(?:register|signup|forgot|reset|login).*["']/i,
  ], { extensions: py });

  const unprotected = [];
  for (const m of routeMatches) {
    const fileContent = await import('fs/promises').then(fs => fs.readFile(m.filePath, 'utf8').catch(() => ''));
    if (!/limiter|limit|slowapi|rate/i.test(fileContent)) {
      unprotected.push(`${path.basename(m.filePath)}:${m.lineNumber}`);
    }
  }

  if (unprotected.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Endpoints de registro/reset pueden carecer de rate limiting',
      description: `Endpoints sensibles sin rate limiter visible: ${unprotected.slice(0, 5).join(', ')}. Son objetivos prioritarios de credential stuffing y abuso automatizado.`,
      code_example:
        '@app.post("/register")\n@limiter.limit("5/minute")\nasync def register(request: Request, body: RegisterSchema): ...',
      cve: null,
    });
  }

  recommendations.push(
    'Añade Cloudflare Turnstile (CAPTCHA invisible) a /register y /forgot-password.',
    'Loguea el User-Agent en todos los eventos de autenticación para análisis de patrones de bot.',
    'Añade rate limiting específico a todos los endpoints de login, registro, recuperación y reset de contraseña.',
    'Implementa velocity tracking para bloquear cuentas tras N fallos por hora, independientemente del rate limit por IP.',
  );

  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = warnCount >= 3 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - warnCount * 12);

  return { id: 'bots', name: 'Bots & Scraping', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express bot protection audit (original logic) ─────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const routesDir = structure.dirs.routes || src;

  const captchaMatches = await grepFiles(src, [/captcha|recaptcha|hcaptcha|turnstile|friendly.captcha/i], { extensions: ['.js'] });
  if (captchaMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No CAPTCHA or proof-of-work on registration and password reset',
      description: 'No CAPTCHA integration found. Registration and password reset endpoints rely solely on rate limiting for bot protection.',
      code_example: null,
      cve: null,
    });
  }

  const uaMatches = await grepFiles(src, [/user.agent|userAgent|req\.headers\[['"`]user-agent['"`]\]/i], { extensions: ['.js'] });
  if (uaMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'User-Agent not logged or filtered',
      description: 'No User-Agent inspection found. Logging User-Agent helps identify bot patterns.',
      code_example: null,
      cve: null,
    });
  }

  const botLibMatches = await grepFiles(src, [/botd|express-bot-detection|isbot|@fingerprintjs/i], { extensions: ['.js'] });
  if (botLibMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No bot detection library detected',
      description: 'No bot detection library (isbot, botd, @fingerprintjs/botd) found.',
      code_example: null,
      cve: null,
    });
  }

  const rateLimitPattern = /rateLimit|rate-limit|throttle|limiter/i;
  const sensitiveRouteMatches = await grepFiles(routesDir, [
    /router\.(get|post|put|delete|patch)\s*\(\s*['"`][^'"`]*(register|signup|forgot|reset)[^'"`]*['"`]/i,
  ], { extensions: ['.js'], contextLines: 5 });

  const unprotectedSensitive = sensitiveRouteMatches.filter(m => {
    const context = m.context.before.join('\n') + m.line + m.context.after.join('\n');
    return !rateLimitPattern.test(context);
  });

  if (unprotectedSensitive.length > 0) {
    const locs = unprotectedSensitive.slice(0, 5).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Registration/reset endpoints may lack rate limiting',
      description: `Found ${unprotectedSensitive.length} sensitive endpoint(s) without a visible rate limiter: ${locs}.`,
      code_example: '// Add rate limiting:\nrouter.post(\'/register\', registerLimiter, registerController)',
      cve: null,
    });
  }

  const loginLogMatches = await grepFiles(src, [/LoginLog|loginLog|login_log/i], { extensions: ['.js'] });
  if (loginLogMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No login velocity/anomaly detection',
      description: 'No LoginLog analysis detected. Brute force campaigns staying under per-request rate limits are not detected.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Add Cloudflare Turnstile (invisible CAPTCHA) to /register and /forgot-password endpoints.',
    'Log User-Agent for all auth events to aid bot pattern analysis.',
    'Add rate limiting to all registration, login, forgot-password, and reset-password endpoints.',
    'Use login velocity tracking to lock accounts after N failures per hour.',
  );

  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = warnCount >= 3 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - warnCount * 12);

  return { id: 'bots', name: 'Bots & Scraping', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
