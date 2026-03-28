/**
 * Spike Test — Pilar C DAST: Prueba de carga en ráfaga
 *
 * Diferente a Slowloris (conexiones lentas):
 *   - Envía N requests rápidas y simultáneas contra cualquier endpoint
 *   - Mide si el rate limiter aguanta bajo carga real
 *   - Detecta degradación de rendimiento, errores 429/5xx, timeouts
 *
 * Uso típico: validar que el rate limiter de una ruta de login, API
 * o endpoint crítico funcione cuando llegan muchas requests en paralelo.
 */
import { URL } from 'url';
import http from 'http';
import https from 'https';

export const meta = {
  id:          'spike-test',
  name:        'Spike Test',
  description: 'Ráfaga de requests concurrentes para validar rate limiting y estabilidad bajo carga',
  risk:        'medium',
  defaultOpts: {
    requests:    500,
    concurrency: 50,
    duration:    30,
    method:      'GET',
  },
};

// ── Rotating User-Agents ──────────────────────────────────────────────────────
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'curl/8.4.0',
  'python-httpx/0.25.0',
  'Go-http-client/2.0',
];

// ── Main runner ───────────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const {
    requests,
    concurrency,
    duration,
    method,
  } = { ...meta.defaultOpts, ...opts };

  const stats = {
    sent:          0,
    ok:            0,
    rateLimited:   0,
    serverErrors:  0,
    timeouts:      0,
    errors:        0,
    statuses:      {},
    responseTimes: [],
    firstRateLimit: null,
    firstError:     null,
  };

  const start    = Date.now();
  let   stopped  = false;
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  hooks.onStart?.({ target, requests, concurrency, duration, method });

  for (let i = 0; i < requests && !stopped; i += concurrency) {
    const batch   = Math.min(concurrency, requests - i);
    const elapsed = Math.round((Date.now() - start) / 1000);

    await Promise.all(Array.from({ length: batch }, async (_, j) => {
      if (stopped) return;
      const ua  = USER_AGENTS[(i + j) % USER_AGENTS.length];
      const t0  = Date.now();
      const res = await makeRequest(target, method, ua);
      const ms  = Date.now() - t0;

      stats.sent++;
      stats.responseTimes.push(ms);
      stats.statuses[res.status] = (stats.statuses[res.status] || 0) + 1;

      if (res.status === 429 || res.status === 403) {
        stats.rateLimited++;
        if (!stats.firstRateLimit) stats.firstRateLimit = stats.sent;
      } else if (res.status >= 500) {
        stats.serverErrors++;
        if (!stats.firstError) stats.firstError = stats.sent;
      } else if (res.status === 0) {
        res.timedOut ? stats.timeouts++ : stats.errors++;
      } else {
        stats.ok++;
      }

      hooks.onRequest?.({ sent: stats.sent, status: res.status, ms, rateLimited: stats.rateLimited });
    }));

    hooks.onBatch?.({
      done:     Math.min(i + batch, requests),
      total:    requests,
      elapsed,
      stats,
    });
  }

  clearTimeout(hardStop);
  const totalMs  = Date.now() - start;

  // ── Compute derived stats ───────────────────────────────────────────────
  const times = stats.responseTimes;
  times.sort((a, b) => a - b);
  const avg  = times.length ? Math.round(times.reduce((s, t) => s + t, 0) / times.length) : 0;
  const p50  = times[Math.floor(times.length * 0.50)] || 0;
  const p95  = times[Math.floor(times.length * 0.95)] || 0;
  const p99  = times[Math.floor(times.length * 0.99)] || 0;
  const rlRatio = stats.sent > 0 ? stats.rateLimited / stats.sent : 0;
  const rps  = stats.sent > 0 ? Math.round(stats.sent / (totalMs / 1000)) : 0;

  // ── Verdict ─────────────────────────────────────────────────────────────
  let severity, verdict;

  if (stats.sent === 0 || (stats.errors + stats.timeouts) === stats.sent) {
    severity = 'low';
    verdict  = 'INCONCLUSO — No se recibieron respuestas del servidor. Verifica la URL y conectividad.';
  } else if (rlRatio >= 0.8 && stats.firstRateLimit <= 20) {
    severity = 'ok';
    verdict  = `RESILIENTE — Rate limiting agresivo activo desde el request #${stats.firstRateLimit}. ${Math.round(rlRatio * 100)}% bloqueados.`;
  } else if (rlRatio >= 0.5) {
    severity = 'medium';
    verdict  = `PARCIAL — ${Math.round(rlRatio * 100)}% de requests bloqueados. Rate limiting activo pero umbral mejorable.`;
  } else if (rlRatio > 0) {
    severity = 'high';
    verdict  = `TARDÍO — Solo ${Math.round(rlRatio * 100)}% bloqueados (primer bloqueo en #${stats.firstRateLimit}). Umbral demasiado alto.`;
  } else if (stats.serverErrors > stats.sent * 0.1) {
    severity = 'high';
    verdict  = `INESTABLE — ${stats.serverErrors} errores 5xx bajo carga. El servidor se degrada antes de aplicar rate limiting.`;
  } else {
    severity = 'critical';
    verdict  = `VULNERABLE — ${stats.sent} requests completados sin ningún bloqueo. Sin rate limiting activo en este endpoint.`;
  }

  const recommendations = buildRecs({ rlRatio, stats, p95, rps, severity });

  return {
    profile: 'spike-test',
    target,
    method,
    severity,
    verdict,
    stats: {
      ...stats,
      responseTimes: undefined,   // omit raw array from report
      avgMs:         avg,
      p50Ms:         p50,
      p95Ms:         p95,
      p99Ms:         p99,
      rps,
      totalMs,
      rateLimitedRatio: Math.round(rlRatio * 100),
    },
    recommendations,
  };
}

// ── HTTP request ──────────────────────────────────────────────────────────────
function makeRequest(url, method = 'GET', userAgent) {
  return new Promise(resolve => {
    try {
      const parsed  = new URL(url);
      const mod     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   method.toUpperCase(),
        headers:  {
          'User-Agent': userAgent || USER_AGENTS[0],
          Accept:       '*/*',
          Connection:   'close',
        },
        rejectUnauthorized: false,
        timeout: 8000,
      };
      const chunks = [];
      const req = mod.request(options, res => {
        res.on('data', d => chunks.push(d));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
      });
      req.on('error', () => resolve({ status: 0, timedOut: false }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, timedOut: true }); });
      if (method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD') req.write('');
      req.end();
    } catch {
      resolve({ status: 0, timedOut: false });
    }
  });
}

// ── Recommendations ───────────────────────────────────────────────────────────
function buildRecs({ rlRatio, stats, p95, rps, severity }) {
  const recs = [];

  if (severity === 'critical' || severity === 'high') {
    recs.push('Implementa rate limiting en este endpoint: máx 60 req/min para usuarios anónimos, 300 para autenticados.');
    recs.push('Usa Redis como backend de rate limiting (express-rate-limit + ioredis) para que funcione en multi-instancia.');
  }
  if (rlRatio > 0 && rlRatio < 0.8) {
    recs.push(`El umbral actual es demasiado permisivo (primer bloqueo en #${stats.firstRateLimit}). Reduce el límite a 20-30 req/min.`);
  }
  if (stats.serverErrors > 0) {
    recs.push(`${stats.serverErrors} errores 5xx bajo carga — revisa los límites de conexión de tu DB o pool de workers.`);
  }
  if (p95 > 2000) {
    recs.push(`P95 de respuesta es ${p95}ms — considera añadir caché o un CDN para rutas públicas.`);
  }
  if (rps > 200 && rlRatio === 0) {
    recs.push('El servidor respondió a más de 200 req/s sin bloquear. Añade protección a nivel de CDN (Cloudflare Rate Limiting Rules).');
  }
  if (!recs.length) {
    recs.push('Rate limiting funcionando correctamente. Considera activar también protección a nivel CDN como segunda capa.');
  }
  return recs;
}
