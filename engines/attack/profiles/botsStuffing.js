/**
 * Credential Stuffing / Bot Simulation
 *
 * Envía ráfagas de peticiones de login con credenciales falsas para verificar:
 *   - ¿Tiene rate limiting? ¿Devuelve 429 después de N intentos?
 *   - ¿Bloquea la cuenta tras N fallos? (lockout)
 *   - ¿Bloquea la IP? ¿Usa CAPTCHA?
 *   - ¿El WAF detecta el patrón de bot?
 *
 * Configurable:
 *   --login-path   /api/auth/login           (required)
 *   --body         '{"email":"{{e}}","password":"{{p}}"}' (o preguntar)
 *   --requests     200
 *   --concurrency  10
 *   --duration     30
 */
import { URL } from 'url';

export const meta = {
  id:          'bots-stuffing',
  name:        'Credential Stuffing',
  description: 'Ráfaga de intentos de login para validar rate limiting, lockout y detección de bots',
  risk:        'medium',
  requiredOpts: ['loginPath'],
  defaultOpts: {
    requests:    200,
    concurrency: 10,
    duration:    30,    // hard stop en segundos aunque no se alcancen los requests
  },
};

// ── Fake credential pool ──────────────────────────────────────────────────────
const EMAILS = [
  'admin@test.com', 'user@test.com', 'root@test.com', 'info@test.com',
  'contact@test.com', 'hello@test.com', 'support@test.com', 'test@test.com',
  'daniel@test.com', 'mail@test.com', 'noreply@test.com', 'dev@test.com',
];
const PASSWORDS = [
  'password', 'password123', '123456', 'admin', 'test', 'qwerty',
  'letmein', 'welcome', 'monkey', 'dragon', '111111', 'master',
  'abc123', 'pass123', 'secret', 'login123',
];
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
  'python-requests/2.31.0',
  'axios/1.6.0',
];

export async function run({ target, opts = {}, hooks = {} }) {
  const { requests, concurrency, duration, loginPath, bodyTemplate } = {
    ...meta.defaultOpts,
    ...opts,
  };

  if (!loginPath) throw new Error('--login-path es requerido para bots-stuffing');

  const base     = new URL(target);
  const loginUrl = `${base.protocol}//${base.host}${loginPath}`;

  // Parse body template — supports {{email}}, {{password}}, {{e}}, {{p}}
  const getBody = (i) => {
    const email    = EMAILS[i % EMAILS.length];
    const password = PASSWORDS[i % PASSWORDS.length];
    if (bodyTemplate) {
      return bodyTemplate
        .replace(/\{\{email\}\}/g, email)
        .replace(/\{\{e\}\}/g, email)
        .replace(/\{\{password\}\}/g, password)
        .replace(/\{\{p\}\}/g, password);
    }
    // Auto-detect: try common patterns
    return JSON.stringify({ email, password });
  };

  const stats = {
    sent: 0, ok: 0, blocked: 0, errors: 0,
    statuses: {},          // { 200: N, 401: N, 429: N, ... }
    firstBlock: null,      // request number when first 429 was seen
    firstLockout: null,    // request number for account lockout signals
    ipBanned: false,
    captchaDetected: false,
    responseTimesMs: [],
  };

  const startTime = Date.now();
  let stopped     = false;

  hooks.onStart?.({ loginUrl, requests, concurrency, duration });

  // Hard stop by duration
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  // ── Send individual request ────────────────────────────────────────────────
  const sendOne = async (i) => {
    if (stopped) return;
    const t0      = Date.now();
    const body    = getBody(i);
    const ua      = USER_AGENTS[i % USER_AGENTS.length];

    try {
      const res = await fetch(loginUrl, {
        method:  'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent':   ua,
          'X-Forwarded-For': randomIP(),   // rotate IPs to test IP-level blocking
        },
        body,
        signal: AbortSignal.timeout(8000),
      });

      const ms     = Date.now() - t0;
      const status = res.status;
      stats.sent++;
      stats.statuses[status] = (stats.statuses[status] || 0) + 1;
      stats.responseTimesMs.push(ms);

      // Detect outcomes
      if (status === 429) {
        stats.blocked++;
        if (!stats.firstBlock) stats.firstBlock = stats.sent;
      } else if (status === 200 || status === 401 || status === 403) {
        stats.ok++;
        // Check response body for lockout signals
        try {
          const text = await res.text();
          if (/lock|locked|blocked|banned|suspend/i.test(text)) {
            if (!stats.firstLockout) stats.firstLockout = stats.sent;
          }
          if (/captcha|recaptcha|hcaptcha|turnstile/i.test(text)) {
            stats.captchaDetected = true;
          }
        } catch {}
      } else if (status === 503 || status === 0) {
        stats.ipBanned = true;
      } else {
        stats.ok++;
      }

      hooks.onRequest?.({ i, sent: stats.sent, status, ms, blocked: stats.blocked });
    } catch (err) {
      stats.errors++;
      // Connection refused after many requests → likely IP banned
      if (err.code === 'ECONNREFUSED' || err.name === 'TimeoutError') {
        stats.ipBanned = true;
      }
      hooks.onRequest?.({ i, sent: stats.sent, status: 'ERR', ms: Date.now() - t0, error: err.message });
    }
  };

  // ── Run in concurrent batches ──────────────────────────────────────────────
  for (let i = 0; i < requests && !stopped; i += concurrency) {
    const batch = Math.min(concurrency, requests - i);
    await Promise.all(Array.from({ length: batch }, (_, j) => sendOne(i + j)));
    hooks.onBatch?.({ done: Math.min(i + batch, requests), total: requests, stats });
  }

  clearTimeout(hardStop);

  // ── Verdict ───────────────────────────────────────────────────────────────
  const blockedRatio  = stats.sent > 0 ? stats.blocked / stats.sent : 0;
  const avgMs         = stats.responseTimesMs.length
    ? Math.round(stats.responseTimesMs.reduce((a, b) => a + b, 0) / stats.responseTimesMs.length)
    : 0;

  let verdict, severity;

  if (stats.ipBanned) {
    verdict  = 'RESILIENTE — la IP fue bloqueada completamente por el servidor o WAF.';
    severity = 'ok';
  } else if (stats.captchaDetected) {
    verdict  = 'RESILIENTE — el servidor devuelve CAPTCHA para detener bots.';
    severity = 'ok';
  } else if (stats.firstBlock && stats.firstBlock <= 10) {
    verdict  = `RESILIENTE — rate limiting activo desde el intento #${stats.firstBlock}.`;
    severity = 'ok';
  } else if (stats.firstLockout) {
    verdict  = `MODERADO — lockout de cuenta detectado en intento #${stats.firstLockout}, pero sin rate limit por IP.`;
    severity = 'medium';
  } else if (blockedRatio > 0.3) {
    verdict  = `PARCIAL — ${Math.round(blockedRatio * 100)}% de requests bloqueados, pero el inicio fue libre.`;
    severity = 'medium';
  } else if (stats.firstBlock) {
    verdict  = `TARDÍO — primer bloqueo en intento #${stats.firstBlock}. Umbral demasiado alto.`;
    severity = 'high';
  } else {
    verdict  = 'VULNERABLE — ningún rate limiting ni lockout detectado tras ' + stats.sent + ' intentos.';
    severity = 'critical';
  }

  return {
    profile: 'bots-stuffing',
    target,
    loginUrl,
    severity,
    verdict,
    stats: {
      ...stats,
      blockedRatio:    Math.round(blockedRatio * 100),
      avgResponseMs:   avgMs,
      durationSeconds: Math.round((Date.now() - startTime) / 1000),
    },
    recommendations: buildRecommendations(severity, stats),
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function randomIP() {
  return `${r(1,254)}.${r(0,255)}.${r(0,255)}.${r(1,254)}`;
}
function r(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function buildRecommendations(severity, stats) {
  const recs = [];
  if (!stats.firstBlock) {
    recs.push('Implementa rate limiting por IP en el endpoint de login: máximo 5-10 intentos en 60 segundos.');
    recs.push('Usa express-rate-limit, Nginx limit_req, o un API Gateway con throttling.');
  }
  if (!stats.firstLockout) {
    recs.push('Implementa lockout de cuenta tras 5 fallos consecutivos con bloqueo temporal (15-30 min).');
  }
  if (!stats.captchaDetected) {
    recs.push('Considera añadir CAPTCHA (hCaptcha, Turnstile) tras 3 intentos fallidos.');
  }
  recs.push('Registra y alerta sobre picos de intentos de login fallidos en tu SIEM.');
  recs.push('Implementa detección de credential stuffing (misma contraseña, emails distintos).');
  if (severity === 'ok') {
    return ['Las defensas funcionan correctamente. Mantén los umbrales ajustados.', ...recs.slice(-2)];
  }
  return recs;
}
