/**
 * Recon — Pilar C DAST: Reconocimiento pasivo
 *
 * Fase 1 del flujo de ataque. No envía tráfico agresivo.
 * Analiza:
 *   - Headers de seguridad HTTP
 *   - Archivos/rutas sensibles expuestos
 *   - Detección de stack tecnológico
 *   - Configuración TLS básica
 *   - CORS policy
 */
import { URL } from 'url';
import http from 'http';
import https from 'https';

export const meta = {
  id:          'recon',
  name:        'Reconnaissance',
  description: 'Reconocimiento pasivo: headers de seguridad, archivos expuestos, tech stack',
  risk:        'low',
  defaultOpts: { timeout: 8000 },
};

// ── Security headers to check ─────────────────────────────────────────────────
const SECURITY_HEADERS = [
  {
    name:     'strict-transport-security',
    label:    'HSTS',
    severity: 'high',
    tip:      'Añade: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  {
    name:     'content-security-policy',
    label:    'CSP',
    severity: 'high',
    tip:      'Añade una Content-Security-Policy restrictiva para prevenir XSS.',
  },
  {
    name:     'x-frame-options',
    label:    'X-Frame-Options',
    severity: 'medium',
    tip:      'Añade: X-Frame-Options: DENY para prevenir clickjacking.',
  },
  {
    name:     'x-content-type-options',
    label:    'X-Content-Type-Options',
    severity: 'medium',
    tip:      'Añade: X-Content-Type-Options: nosniff',
  },
  {
    name:     'referrer-policy',
    label:    'Referrer-Policy',
    severity: 'low',
    tip:      'Añade: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name:     'permissions-policy',
    label:    'Permissions-Policy',
    severity: 'low',
    tip:      'Añade Permissions-Policy para limitar acceso a APIs del navegador.',
  },
  {
    name:     'x-xss-protection',
    label:    'X-XSS-Protection',
    severity: 'low',
    tip:      'Considera añadir: X-XSS-Protection: 1; mode=block (legacy browsers).',
  },
];

// ── Sensitive paths to probe ──────────────────────────────────────────────────
const SENSITIVE_PATHS = [
  { path: '/.env',             label: '.env expuesto',         severity: 'critical' },
  { path: '/.env.local',       label: '.env.local expuesto',   severity: 'critical' },
  { path: '/.env.production',  label: '.env.production',       severity: 'critical' },
  { path: '/.git/HEAD',        label: '.git expuesto',         severity: 'critical' },
  { path: '/wp-admin',         label: 'Panel WordPress',       severity: 'high'     },
  { path: '/wp-login.php',     label: 'Login WordPress',       severity: 'high'     },
  { path: '/admin',            label: 'Panel /admin',          severity: 'high'     },
  { path: '/administrator',    label: 'Panel /administrator',  severity: 'high'     },
  { path: '/api/docs',         label: 'Docs API expuestos',    severity: 'medium'   },
  { path: '/api-docs',         label: 'Docs API expuestos',    severity: 'medium'   },
  { path: '/swagger',          label: 'Swagger UI expuesto',   severity: 'medium'   },
  { path: '/swagger-ui.html',  label: 'Swagger UI expuesto',   severity: 'medium'   },
  { path: '/graphql',          label: 'GraphQL expuesto',      severity: 'medium'   },
  { path: '/graphiql',         label: 'GraphiQL expuesto',     severity: 'medium'   },
  { path: '/robots.txt',       label: 'robots.txt',            severity: 'info'     },
  { path: '/sitemap.xml',      label: 'sitemap.xml',           severity: 'info'     },
  { path: '/.well-known/security.txt', label: 'security.txt', severity: 'info'     },
  { path: '/server-status',    label: 'Apache server-status',  severity: 'high'     },
  { path: '/phpinfo.php',      label: 'phpinfo() expuesto',    severity: 'critical' },
  { path: '/config.json',      label: 'config.json expuesto',  severity: 'critical' },
  { path: '/package.json',     label: 'package.json expuesto', severity: 'high'     },
];

// ── Tech stack fingerprints ───────────────────────────────────────────────────
const TECH_FINGERPRINTS = [
  { header: 'server',            pattern: /nginx/i,         tech: 'Nginx'          },
  { header: 'server',            pattern: /apache/i,        tech: 'Apache'         },
  { header: 'server',            pattern: /cloudflare/i,    tech: 'Cloudflare'     },
  { header: 'server',            pattern: /vercel/i,        tech: 'Vercel'         },
  { header: 'x-powered-by',      pattern: /next\.js/i,      tech: 'Next.js'        },
  { header: 'x-powered-by',      pattern: /express/i,       tech: 'Express.js'     },
  { header: 'x-powered-by',      pattern: /php/i,           tech: 'PHP'            },
  { header: 'x-vercel-id',       pattern: /.*/,             tech: 'Vercel'         },
  { header: 'cf-ray',            pattern: /.*/,             tech: 'Cloudflare CDN' },
  { header: 'x-amz-cf-id',       pattern: /.*/,             tech: 'AWS CloudFront' },
  { header: 'x-cache',           pattern: /cloudfront/i,    tech: 'AWS CloudFront' },
  { header: 'x-railway-edge',    pattern: /.*/,             tech: 'Railway'        },
  { header: 'x-render-origin-server', pattern: /.*/,        tech: 'Render.com'     },
];

// ── CORS check ────────────────────────────────────────────────────────────────
const CORS_ORIGINS_TO_TEST = ['https://evil.com', 'null', 'https://attacker.io'];

// ── Main runner ───────────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const timeout = opts.timeout || meta.defaultOpts.timeout;
  const base    = new URL(target);

  hooks.onPhase?.('recon', `Analizando ${target}`);

  // 1. Fetch main page headers
  const mainRes = await fetchHead(target, timeout);
  hooks.onPhase?.('headers', 'Comprobando headers de seguridad');

  // 2. Check security headers
  const headerFindings = [];
  for (const h of SECURITY_HEADERS) {
    const present = h.name in (mainRes.headers || {});
    const value   = mainRes.headers?.[h.name] || null;
    headerFindings.push({ ...h, present, value });
    hooks.onHeaderCheck?.({ label: h.label, present, value, severity: h.severity });
  }

  // 3. Detect tech stack
  const tech = detectTech(mainRes.headers || {});
  hooks.onTechDetected?.(tech);

  // 4. Check for information leaks via Server/X-Powered-By
  const infoLeaks = [];
  if (mainRes.headers?.server) infoLeaks.push({ type: 'Server header', value: mainRes.headers.server });
  if (mainRes.headers?.['x-powered-by']) infoLeaks.push({ type: 'X-Powered-By', value: mainRes.headers['x-powered-by'] });
  if (mainRes.headers?.via) infoLeaks.push({ type: 'Via', value: mainRes.headers.via });

  // 5. Probe sensitive paths
  hooks.onPhase?.('paths', 'Escaneando rutas sensibles');
  const pathFindings = [];
  for (const p of SENSITIVE_PATHS) {
    const url = base.origin + p.path;
    const res = await fetchHead(url, timeout);
    const found = res.status !== 404 && res.status !== 0;
    if (found) {
      pathFindings.push({ ...p, status: res.status, url });
    }
    hooks.onPathProbe?.({ ...p, status: res.status, found });
  }

  // 6. CORS check
  hooks.onPhase?.('cors', 'Comprobando política CORS');
  const corsFindings = [];
  for (const origin of CORS_ORIGINS_TO_TEST) {
    const res = await fetchWithOrigin(target, origin, timeout);
    const acao = res.headers?.['access-control-allow-origin'];
    if (acao === origin || acao === '*') {
      corsFindings.push({ origin, acao, severity: acao === '*' ? 'high' : 'critical' });
    }
    hooks.onCorsCheck?.({ origin, acao, vulnerable: !!corsFindings.find(f => f.origin === origin) });
  }

  // ── Build result ─────────────────────────────────────────────────────────
  const missingCritical = headerFindings.filter(h => !h.present && h.severity === 'high');
  const missingMedium   = headerFindings.filter(h => !h.present && h.severity === 'medium');
  const criticalPaths   = pathFindings.filter(p => p.severity === 'critical');
  const highPaths       = pathFindings.filter(p => p.severity === 'high');

  let severity, verdict;
  if (criticalPaths.length || corsFindings.some(f => f.severity === 'critical')) {
    severity = 'critical';
    verdict  = `CRÍTICO — ${criticalPaths.length} archivos sensibles expuestos${corsFindings.length ? ' + CORS misconfigured' : ''}.`;
  } else if (highPaths.length || missingCritical.length || corsFindings.length) {
    severity = 'high';
    verdict  = `ALTO RIESGO — Faltan ${missingCritical.length} headers críticos, ${highPaths.length} rutas de riesgo alto.`;
  } else if (missingMedium.length || pathFindings.length) {
    severity = 'medium';
    verdict  = `MODERADO — ${missingMedium.length} headers de seguridad ausentes. Sin rutas críticas expuestas.`;
  } else {
    severity = 'ok';
    verdict  = 'BUENA CONFIGURACIÓN — Headers de seguridad presentes, sin archivos sensibles expuestos.';
  }

  const recommendations = buildRecs({ missingCritical, missingMedium, criticalPaths, highPaths, corsFindings, infoLeaks, headerFindings });

  return {
    profile:       'recon',
    target,
    severity,
    verdict,
    tech,
    infoLeaks,
    headerFindings,
    pathFindings,
    corsFindings,
    stats: {
      headersChecked:  SECURITY_HEADERS.length,
      headersMissing:  headerFindings.filter(h => !h.present).length,
      pathsProbed:     SENSITIVE_PATHS.length,
      pathsFound:      pathFindings.length,
      corsVulnerable:  corsFindings.length > 0,
      statusCode:      mainRes.status,
    },
    recommendations,
  };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function fetchHead(url, timeout = 8000) {
  return new Promise(resolve => {
    try {
      const parsed  = new URL(url);
      const mod     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   'HEAD',
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; FractiaRecon/3.0)', Accept: '*/*' },
        rejectUnauthorized: false,
        timeout,
      };
      const req = mod.request(options, res => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
      });
      req.on('error', () => resolve({ status: 0, headers: {} }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {} }); });
      req.end();
    } catch {
      resolve({ status: 0, headers: {} });
    }
  });
}

function fetchWithOrigin(url, origin, timeout = 8000) {
  return new Promise(resolve => {
    try {
      const parsed  = new URL(url);
      const mod     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   'GET',
        headers:  {
          'User-Agent': 'Mozilla/5.0 (compatible; FractiaRecon/3.0)',
          'Origin':     origin,
        },
        rejectUnauthorized: false,
        timeout,
      };
      const req = mod.request(options, res => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
      });
      req.on('error', () => resolve({ status: 0, headers: {} }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {} }); });
      req.end();
    } catch {
      resolve({ status: 0, headers: {} });
    }
  });
}

function detectTech(headers) {
  const detected = new Set();
  for (const fp of TECH_FINGERPRINTS) {
    const val = headers[fp.header];
    if (val && fp.pattern.test(val)) detected.add(fp.tech);
  }
  return [...detected];
}

function buildRecs({ missingCritical, missingMedium, criticalPaths, highPaths, corsFindings, infoLeaks, headerFindings }) {
  const recs = [];
  for (const h of [...missingCritical, ...missingMedium]) {
    recs.push(h.tip);
  }
  for (const p of criticalPaths) {
    recs.push(`Bloquea el acceso a ${p.path} — ${p.label} expuesto (HTTP ${p.status}).`);
  }
  for (const p of highPaths) {
    recs.push(`Revisa si ${p.path} debe ser público (HTTP ${p.status}).`);
  }
  for (const c of corsFindings) {
    recs.push(`CORS misconfigured: el servidor acepta Origin "${c.origin}" → Access-Control-Allow-Origin: ${c.acao}. Usa una whitelist explícita.`);
  }
  if (infoLeaks.length) {
    recs.push(`Oculta información del servidor: elimina o vacía los headers ${infoLeaks.map(l => l.type).join(', ')}.`);
  }
  if (!recs.length) recs.push('Configuración de seguridad correcta. Mantén las dependencias actualizadas.');
  return recs;
}
