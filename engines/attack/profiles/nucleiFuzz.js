/**
 * nucleiFuzz.js — Nuclei Template Scanner (Pilar C DAST)
 *
 * Ejecuta el motor de fuzzing de Nuclei contra la URL objetivo.
 * Nuclei usa plantillas YAML que cubren miles de CVEs, misconfigurations,
 * exposures, default credentials, etc.
 *
 * Requisitos:
 *   - nuclei instalado: https://github.com/projectdiscovery/nuclei
 *     go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
 *     o descargable desde https://nuclei.projectdiscovery.io/
 *
 * Si nuclei no está disponible, ejecuta un fuzzer HTTP propio (built-in)
 * que cubre las plantillas más comunes de forma nativa.
 */
import { spawn, execSync } from 'child_process';
import { createWriteStream, existsSync, unlinkSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import http from 'http';
import https from 'https';
import { URL } from 'url';

export const meta = {
  id:          'nuclei-fuzz',
  name:        'Nuclei Fuzzer',
  description: 'Fuzzing con plantillas Nuclei — CVEs, misconfigs, exposed panels, default creds',
  risk:        'medium',
  defaultOpts: {
    severity:  ['low', 'medium', 'high', 'critical'],
    tags:      [],          // e.g. ['cve', 'exposed', 'misconfig']
    templates: [],          // rutas a templates específicos
    timeout:   90,          // segundos
    rateLimit: 150,         // req/s
    concurrency: 25,
  },
};

// ── Severidad Nuclei → Fractia ────────────────────────────────────────────────
const SEV_MAP = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'low', unknown: 'low' };

// ── Comprobación de herramienta ────────────────────────────────────────────────
function which(cmd) {
  try { execSync(`which ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}

function isNucleiAvailable() {
  return which('nuclei');
}

// ── Runner principal ───────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const available = isNucleiAvailable();
  hooks.onPhase?.('init', available ? 'Nuclei detectado' : 'Nuclei no encontrado — usando fuzzer built-in');

  if (!available) {
    return await builtinFuzz({ target, opts, hooks });
  }

  return await runNuclei({ target, opts, hooks });
}

// ── Nuclei runner ─────────────────────────────────────────────────────────────
async function runNuclei({ target, opts, hooks }) {
  const timeout     = opts.timeout     || meta.defaultOpts.timeout;
  const rateLimit   = opts.rateLimit   || meta.defaultOpts.rateLimit;
  const concurrency = opts.concurrency || meta.defaultOpts.concurrency;
  const severities  = (opts.severity   || meta.defaultOpts.severity).join(',');
  const outputFile  = path.join(tmpdir(), `fractia-nuclei-${Date.now()}.jsonl`);

  const args = [
    '-u', target,
    '-json-export', outputFile,
    '-severity', severities,
    '-rate-limit', String(rateLimit),
    '-concurrency', String(concurrency),
    '-timeout', String(timeout),
    '-no-color',
    '-silent',
    '-stats',
  ];

  if (opts.tags?.length)      args.push('-tags', opts.tags.join(','));
  if (opts.templates?.length) { for (const t of opts.templates) args.push('-t', t); }

  hooks.onPhase?.('scan', `Ejecutando nuclei contra ${target}…`);

  let exitCode = 0;
  try {
    exitCode = await spawnNuclei(args, hooks, (timeout + 30) * 1000);
  } catch (err) {
    hooks.onNucleiLog?.(`[error] ${err.message}`);
    return await builtinFuzz({ target, opts, hooks, note: `Nuclei falló: ${err.message}` });
  }

  const findings = parseNucleiOutput(outputFile);
  try { if (existsSync(outputFile)) unlinkSync(outputFile); } catch {}

  return buildResult({ target, findings, runner: 'nuclei', exitCode });
}

// ── Spawn Nuclei con streaming ─────────────────────────────────────────────────
function spawnNuclei(args, hooks, timeoutMs) {
  return new Promise((resolve, reject) => {
    const proc = spawn('nuclei', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let lastLine = '';

    proc.stdout.on('data', chunk => {
      const lines = (lastLine + chunk.toString()).split('\n');
      lastLine = lines.pop();
      for (const line of lines) {
        const clean = line.trim();
        if (clean) {
          hooks.onNucleiLog?.(clean);
          // Live findings: Nuclei con -silent imprime findings en stdout como JSON
          try {
            const obj = JSON.parse(clean);
            if (obj['template-id']) hooks.onNucleiFinding?.(obj);
          } catch {}
        }
      }
    });

    proc.stderr.on('data', chunk => {
      chunk.toString().split('\n').forEach(l => {
        const clean = l.trim();
        if (clean) hooks.onNucleiLog?.(`[stats] ${clean}`);
      });
    });

    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      reject(new Error(`Nuclei timeout (>${timeoutMs / 1000}s)`));
    }, timeoutMs);

    proc.on('close', code => { clearTimeout(timer); resolve(code ?? 0); });
    proc.on('error', err   => { clearTimeout(timer); reject(err); });
  });
}

// ── Parser del output JSONL de Nuclei ─────────────────────────────────────────
function parseNucleiOutput(outputFile) {
  if (!existsSync(outputFile)) return [];

  const raw = readFileSync(outputFile, 'utf8');
  const findings = [];

  for (const line of raw.split('\n')) {
    const clean = line.trim();
    if (!clean) continue;
    try {
      const obj = JSON.parse(clean);
      findings.push({
        type:        'finding',
        templateId:  obj['template-id'] || '',
        name:        obj.info?.name    || obj['template-id'] || 'Nuclei Finding',
        severity:    SEV_MAP[obj.info?.severity] || 'low',
        description: obj.info?.description || '',
        tags:        obj.info?.tags    || [],
        reference:   (obj.info?.reference || []).join(', '),
        cveId:       obj.info?.classification?.['cve-id']?.[0] || '',
        cweId:       obj.info?.classification?.['cwe-id']?.[0] || '',
        url:         obj.matched_at    || obj.host || '',
        matcher:     obj['matcher-name'] || '',
        extractors:  obj['extracted-results'] || [],
        curl:        obj['curl-command'] || '',
        timestamp:   obj.timestamp || new Date().toISOString(),
      });
    } catch {}
  }

  return findings;
}

// ── Built-in Fuzzer (fallback cuando nuclei no está instalado) ─────────────────
// Cubre las plantillas Nuclei más populares de forma nativa con peticiones HTTP.
const BUILTIN_CHECKS = [

  // ── Exposed panels ────────────────────────────────────────────────────────
  { path: '/wp-login.php',        title: 'WordPress login expuesto',       severity: 'medium', tag: 'exposed'  },
  { path: '/wp-admin/',           title: 'WordPress admin expuesto',        severity: 'high',   tag: 'exposed'  },
  { path: '/admin/',              title: 'Panel /admin accesible',          severity: 'high',   tag: 'exposed'  },
  { path: '/administrator/',      title: 'Panel /administrator accesible',  severity: 'high',   tag: 'exposed'  },
  { path: '/phpmyadmin/',         title: 'phpMyAdmin expuesto',             severity: 'critical',tag: 'exposed' },
  { path: '/phpmyadmin/index.php',title: 'phpMyAdmin expuesto',             severity: 'critical',tag: 'exposed' },

  // ── Sensitive files ───────────────────────────────────────────────────────
  { path: '/.env',                title: '.env expuesto',                   severity: 'critical', tag: 'exposure' },
  { path: '/.env.production',     title: '.env.production expuesto',        severity: 'critical', tag: 'exposure' },
  { path: '/.git/config',         title: 'Git config expuesto',             severity: 'critical', tag: 'exposure' },
  { path: '/.git/HEAD',           title: '.git HEAD expuesto',              severity: 'critical', tag: 'exposure' },
  { path: '/config.json',         title: 'config.json expuesto',            severity: 'critical', tag: 'exposure' },
  { path: '/config.yml',          title: 'config.yml expuesto',             severity: 'critical', tag: 'exposure' },
  { path: '/package.json',        title: 'package.json expuesto',           severity: 'high',     tag: 'exposure' },
  { path: '/server.key',          title: 'Clave privada expuesta',          severity: 'critical', tag: 'exposure' },
  { path: '/id_rsa',              title: 'Clave SSH expuesta',              severity: 'critical', tag: 'exposure' },
  { path: '/backup.sql',          title: 'Backup SQL expuesto',             severity: 'critical', tag: 'exposure' },
  { path: '/dump.sql',            title: 'Dump SQL expuesto',               severity: 'critical', tag: 'exposure' },
  { path: '/phpinfo.php',         title: 'phpinfo() expuesto',              severity: 'critical', tag: 'exposure' },

  // ── API & docs ────────────────────────────────────────────────────────────
  { path: '/swagger-ui.html',     title: 'Swagger UI expuesto',             severity: 'medium', tag: 'exposure' },
  { path: '/swagger.json',        title: 'Swagger JSON expuesto',           severity: 'medium', tag: 'exposure' },
  { path: '/openapi.json',        title: 'OpenAPI spec expuesto',           severity: 'medium', tag: 'exposure' },
  { path: '/api-docs',            title: 'API Docs expuestos',              severity: 'medium', tag: 'exposure' },
  { path: '/graphql',             title: 'GraphQL expuesto',                severity: 'medium', tag: 'exposure' },
  { path: '/graphiql',            title: 'GraphiQL expuesto',               severity: 'high',   tag: 'exposure' },

  // ── Default credentials probe (check if login form exists) ────────────────
  { path: '/login',               title: 'Login endpoint detectable',       severity: 'info',   tag: 'default-login', checkFn: probeLoginForm  },
  { path: '/auth/login',          title: 'Login endpoint detectable',       severity: 'info',   tag: 'default-login', checkFn: probeLoginForm  },

  // ── Common misconfigs ─────────────────────────────────────────────────────
  { path: '/server-status',       title: 'Apache server-status expuesto',   severity: 'high',   tag: 'misconfig' },
  { path: '/server-info',         title: 'Apache server-info expuesto',     severity: 'high',   tag: 'misconfig' },
  { path: '/_profiler',           title: 'Symfony Profiler expuesto',       severity: 'high',   tag: 'misconfig' },
  { path: '/debug/pprof',         title: 'Go pprof expuesto',               severity: 'high',   tag: 'misconfig' },
  { path: '/metrics',             title: 'Prometheus metrics expuesto',     severity: 'medium', tag: 'misconfig' },
  { path: '/actuator',            title: 'Spring Boot Actuator expuesto',   severity: 'high',   tag: 'misconfig' },
  { path: '/actuator/env',        title: 'Spring Boot env expuesto',        severity: 'critical',tag:'misconfig' },
  { path: '/actuator/heapdump',   title: 'Spring Boot heapdump expuesto',   severity: 'critical',tag:'misconfig' },
  { path: '/.htaccess',           title: '.htaccess accesible',             severity: 'medium', tag: 'misconfig' },
  { path: '/web.config',          title: 'web.config expuesto',             severity: 'high',   tag: 'misconfig' },
  { path: '/crossdomain.xml',     title: 'crossdomain.xml permisivo',       severity: 'medium', tag: 'misconfig' },
  { path: '/clientaccesspolicy.xml', title: 'clientaccesspolicy.xml',       severity: 'medium', tag: 'misconfig' },
];

async function builtinFuzz({ target, opts, hooks, note }) {
  hooks.onPhase?.('builtin', `Built-in fuzzer activo — ${BUILTIN_CHECKS.length} checks`);

  const base     = new URL(target);
  const findings = [];
  let checked    = 0;

  for (const check of BUILTIN_CHECKS) {
    const url = base.origin + check.path;
    try {
      let finding = null;
      if (check.checkFn) {
        finding = await check.checkFn(url, check);
      } else {
        const res = await httpGet(url, 6000);
        if (res.status === 200 || res.status === 301 || res.status === 302) {
          finding = {
            type:        'finding',
            templateId:  `builtin:${check.tag}`,
            name:        check.title,
            severity:    check.severity,
            description: `${url} accesible (HTTP ${res.status})`,
            tags:        [check.tag],
            url,
          };
        }
      }
      if (finding) {
        findings.push(finding);
        hooks.onNucleiFinding?.(finding);
      }
      checked++;
      hooks.onNucleiLog?.(`[${checked}/${BUILTIN_CHECKS.length}] ${check.path} → ${finding ? finding.severity.toUpperCase() : 'OK'}`);
    } catch {
      hooks.onNucleiLog?.(`  - ${check.path}: error`);
    }
  }

  const result = buildResult({ target, findings, runner: 'builtin', exitCode: 0 });

  if (note) {
    result.recommendations.unshift(note);
  }
  result.recommendations.unshift(
    'Instala Nuclei para plantillas completas (miles de CVEs):',
    '  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    '  o descarga en: https://nuclei.projectdiscovery.io/'
  );

  return result;
}

// ── Construir resultado estandarizado ─────────────────────────────────────────
function buildResult({ target, findings, runner, exitCode }) {
  findings.sort((a, b) => {
    const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (ORDER[a.severity] ?? 5) - (ORDER[b.severity] ?? 5);
  });

  const critical = findings.filter(f => f.severity === 'critical');
  const high     = findings.filter(f => f.severity === 'high');
  const medium   = findings.filter(f => f.severity === 'medium');
  const low      = findings.filter(f => f.severity === 'low' || f.severity === 'info');

  let severity, verdict;
  if (critical.length) {
    severity = 'critical';
    verdict  = `CRÍTICO — ${critical.length} hallazgos críticos. Requiere acción inmediata.`;
  } else if (high.length) {
    severity = 'high';
    verdict  = `ALTO — ${high.length} hallazgos de alto riesgo en el fuzzing.`;
  } else if (medium.length) {
    severity = 'medium';
    verdict  = `MEDIO — ${medium.length} hallazgos de riesgo moderado.`;
  } else if (low.length) {
    severity = 'low';
    verdict  = `BAJO — Solo ${low.length} hallazgos informativos. Buena postura.`;
  } else {
    severity = 'ok';
    verdict  = 'SIN HALLAZGOS — Nuclei no encontró vulnerabilidades conocidas.';
  }

  return {
    profile:  'nuclei-fuzz',
    target,
    severity,
    verdict,
    runner,
    exitCode,
    findings,
    stats: {
      total:    findings.length,
      critical: critical.length,
      high:     high.length,
      medium:   medium.length,
      low:      low.length,
    },
    recommendations: buildRecs(findings),
  };
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function httpGet(url, timeout = 6000) {
  return new Promise(resolve => {
    try {
      const parsed  = new URL(url);
      const mod     = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   'GET',
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; FractiaFuzz/3.0)' },
        rejectUnauthorized: false,
        timeout,
      };
      let body = '';
      const req = mod.request(options, res => {
        res.on('data', d => { if (body.length < 8192) body += d; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '' }); });
      req.end();
    } catch {
      resolve({ status: 0, headers: {}, body: '' });
    }
  });
}

async function probeLoginForm(url, check) {
  const res = await httpGet(url, 6000);
  if (res.status === 0 || res.status === 404) return null;
  const hasForm = /<form/i.test(res.body);
  if (!hasForm) return null;
  const noCSRF = !/csrf|_token|nonce|authenticity_token/i.test(res.body);
  return {
    type:        'finding',
    templateId:  `builtin:default-login`,
    name:        check.title + (noCSRF ? ' (sin CSRF)' : ''),
    severity:    noCSRF ? 'high' : 'medium',
    description: `Formulario de login en ${url}${noCSRF ? ' — sin token CSRF visible.' : '.'}`,
    tags:        ['default-login', noCSRF ? 'csrf' : 'info'],
    url,
  };
}

// ── Recomendaciones ───────────────────────────────────────────────────────────
function buildRecs(findings) {
  const recs = new Set();
  for (const f of findings) {
    if (f.severity === 'critical') {
      recs.add(`[CRÍTICO] Elimina o protege: ${f.url || f.name}`);
    } else if (f.severity === 'high') {
      recs.add(`[ALTO] Revisa y restringe acceso: ${f.name}`);
    }
    if (f.reference) recs.add(`Referencia: ${f.reference}`);
  }
  if (!recs.size) recs.add('Sin hallazgos. Ejecuta con nuclei instalado para cobertura completa de CVEs.');
  return [...recs];
}
