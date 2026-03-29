/**
 * zapScan.js — OWASP ZAP Integration (Pilar C DAST)
 *
 * Ejecuta un escaneo DAST con OWASP ZAP contra la URL objetivo.
 * Soporta tres modos de ejecución (en orden de preferencia):
 *   1. ZAP instalado localmente  (zaproxy / zap.sh en PATH)
 *   2. Docker Desktop disponible (imagen ghcr.io/zaproxy/zaproxy:stable)
 *   3. Fallback: reconocimiento propio de Fractia + aviso de instalación
 *
 * Tipo de escaneo: Baseline Scan (spider pasivo + reglas pasivas)
 * Para un active scan completo, configura opts.mode = 'active'.
 */
import { spawn, execSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import http from 'http';
import https from 'https';
import { URL } from 'url';

export const meta = {
  id:          'zap-scan',
  name:        'OWASP ZAP Scan',
  description: 'DAST completo con OWASP ZAP — spider pasivo + reglas de vulnerabilidad',
  risk:        'medium',
  defaultOpts: {
    mode:    'baseline',  // 'baseline' | 'active'
    timeout: 120,         // segundos
    ajaxSpider: false,
  },
};

// ── Mapeo de niveles de riesgo ZAP → Fractia ──────────────────────────────────
const RISK_MAP = { 3: 'critical', 2: 'high', 1: 'medium', 0: 'low' };

// ── Comprobaciones de herramienta disponible ──────────────────────────────────
function which(cmd) {
  try { execSync(`which ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}

function isDockerAvailable() {
  try { execSync('docker info', { stdio: 'ignore', timeout: 5000 }); return true; } catch { return false; }
}

function detectZapMode() {
  if (which('zaproxy') || which('zap.sh') || which('zap-cli')) return 'local';
  if (isDockerAvailable()) return 'docker';
  return 'none';
}

// ── Runner principal ───────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const mode    = opts.mode    || meta.defaultOpts.mode;
  const timeout = opts.timeout || meta.defaultOpts.timeout;
  const zapMode = detectZapMode();

  hooks.onPhase?.('init', `ZAP detectado: ${zapMode}`);

  if (zapMode === 'none') {
    hooks.onPhase?.('fallback', 'ZAP no encontrado — ejecutando reconocimiento básico');
    return await fallbackScan({ target, hooks, mode });
  }

  const reportPath = path.join(tmpdir(), `fractia-zap-${Date.now()}.json`);

  try {
    if (zapMode === 'docker') {
      return await runWithDocker({ target, mode, timeout, reportPath, hooks });
    } else {
      return await runLocal({ target, mode, timeout, reportPath, hooks });
    }
  } catch (err) {
    hooks.onPhase?.('error', `ZAP falló: ${err.message} — usando fallback`);
    return await fallbackScan({ target, hooks, mode });
  } finally {
    try { if (existsSync(reportPath)) unlinkSync(reportPath); } catch {}
  }
}

// ── Docker runner ─────────────────────────────────────────────────────────────
async function runWithDocker({ target, mode, timeout, reportPath, hooks }) {
  hooks.onPhase?.('docker', 'Iniciando ZAP via Docker…');

  const containerReport = '/zap/wrk/report.json';
  const wrk = path.dirname(reportPath);
  const localReport = path.join(wrk, 'report.json');

  const zapScript = mode === 'active' ? 'zap-full-scan.py' : 'zap-baseline.py';

  const args = [
    'run', '--rm',
    '-v', `${wrk}:/zap/wrk:rw`,
    'ghcr.io/zaproxy/zaproxy:stable',
    zapScript,
    '-t', target,
    '-J', 'report.json',
    '-I',                // no-fail on warn
    '-T', String(timeout),
  ];

  await spawnAndStream('docker', args, hooks, timeout * 1000 + 30000);

  if (!existsSync(localReport)) {
    throw new Error('Docker no generó el reporte JSON de ZAP');
  }

  const raw = JSON.parse(readFileSync(localReport, 'utf8'));
  try { unlinkSync(localReport); } catch {}
  return parseZapReport(raw, target, mode, 'docker');
}

// ── Local runner ──────────────────────────────────────────────────────────────
async function runLocal({ target, mode, timeout, reportPath, hooks }) {
  hooks.onPhase?.('local', 'Iniciando ZAP local…');

  const zapBin = which('zaproxy') ? 'zaproxy' : which('zap.sh') ? 'zap.sh' : 'zap-cli';
  const zapScript = mode === 'active' ? 'zap-full-scan.py' : 'zap-baseline.py';

  let args;
  if (zapBin === 'zap-cli') {
    // zap-cli approach: start ZAP daemon first
    args = ['quick-scan', '--self-contained', '--start-options', '-config api.disablekey=true', '-s', 'xss,sqli', target];
  } else {
    args = [
      '-cmd',
      `-quickurl`, target,
      `-quickout`, reportPath,
      `-quickprogress`,
    ];
  }

  await spawnAndStream(zapBin, args, hooks, timeout * 1000 + 30000);

  if (!existsSync(reportPath)) {
    throw new Error('ZAP local no generó el reporte JSON');
  }

  const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
  return parseZapReport(raw, target, mode, 'local');
}

// ── Spawn helper con streaming de output ─────────────────────────────────────
function spawnAndStream(cmd, args, hooks, timeoutMs) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let lastLine = '';

    proc.stdout.on('data', chunk => {
      const lines = (lastLine + chunk.toString()).split('\n');
      lastLine = lines.pop();
      for (const line of lines) {
        const clean = line.trim();
        if (clean) hooks.onZapLog?.(clean);
      }
    });

    proc.stderr.on('data', chunk => {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        const clean = line.trim();
        if (clean) hooks.onZapLog?.(`[err] ${clean}`);
      }
    });

    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      reject(new Error(`ZAP timeout (>${timeoutMs / 1000}s)`));
    }, timeoutMs);

    proc.on('close', code => {
      clearTimeout(timer);
      // ZAP exits 2 when there are findings — that's OK
      if (code === 0 || code === 2) resolve(code);
      else reject(new Error(`ZAP salió con código ${code}`));
    });

    proc.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ── Parser del reporte JSON de ZAP ────────────────────────────────────────────
function parseZapReport(raw, target, mode, runner) {
  const alerts = [];

  // ZAP report format: { site: [{ alerts: [...] }] } or { alerts: [...] }
  const sites = raw.site || raw.sites || (raw.alerts ? [raw] : []);

  for (const site of (Array.isArray(sites) ? sites : [sites])) {
    for (const alert of (site.alerts || [])) {
      const risk     = parseInt(alert.riskcode ?? alert.risk ?? 0, 10);
      const severity = RISK_MAP[risk] ?? 'low';

      alerts.push({
        type:        'finding',
        title:       alert.name || alert.alert || 'ZAP Alert',
        severity,
        description: alert.desc  || alert.description || '',
        solution:    alert.solution || '',
        reference:   alert.reference || '',
        url:         alert.instances?.[0]?.uri || alert.url || target,
        param:       alert.instances?.[0]?.param || alert.param || '',
        evidence:    alert.instances?.[0]?.evidence || alert.evidence || '',
        pluginId:    alert.pluginid || '',
        cweId:       alert.cweid  || '',
        wascId:      alert.wascid || '',
        count:       parseInt(alert.count ?? 1, 10),
      });
    }
  }

  // Sort by severity
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  alerts.sort((a, b) => (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4));

  const critical = alerts.filter(a => a.severity === 'critical');
  const high     = alerts.filter(a => a.severity === 'high');
  const medium   = alerts.filter(a => a.severity === 'medium');
  const low      = alerts.filter(a => a.severity === 'low');

  let severity, verdict;
  if (critical.length) {
    severity = 'critical';
    verdict  = `CRÍTICO — ${critical.length} vulnerabilidades críticas encontradas por ZAP.`;
  } else if (high.length) {
    severity = 'high';
    verdict  = `ALTO — ${high.length} alertas de alto riesgo en el escaneo ZAP.`;
  } else if (medium.length) {
    severity = 'medium';
    verdict  = `MEDIO — ${medium.length} alertas de riesgo moderado.`;
  } else if (low.length) {
    severity = 'low';
    verdict  = `BAJO — Solo ${low.length} alertas de bajo riesgo. Buena postura de seguridad.`;
  } else {
    severity = 'ok';
    verdict  = 'SIN HALLAZGOS — ZAP no encontró vulnerabilidades en el baseline scan.';
  }

  const recommendations = buildRecs(alerts);

  return {
    profile: 'zap-scan',
    target,
    severity,
    verdict,
    runner,
    mode,
    alerts,
    stats: {
      total:    alerts.length,
      critical: critical.length,
      high:     high.length,
      medium:   medium.length,
      low:      low.length,
    },
    recommendations,
  };
}

// ── Fallback: reconocimiento básico cuando ZAP no está instalado ──────────────
async function fallbackScan({ target, hooks, mode }) {
  hooks.onPhase?.('fallback', 'ZAP no disponible — ejecutando reconocimiento HTTP básico');

  const base    = new URL(target);
  const results = [];

  // Check common vuln indicators via HTTP
  const checks = [
    { path: '/',                    test: checkHeadersBasic,   label: 'Security headers' },
    { path: '/login',               test: checkLoginForm,      label: 'Login endpoint' },
    { path: '/api',                 test: checkApiEndpoint,    label: 'API exposure'   },
    { path: '/admin',               test: checkSensitivePath,  label: 'Admin panel'    },
    { path: '/.env',                test: checkSensitivePath,  label: '.env exposed'   },
    { path: '/config.json',         test: checkSensitivePath,  label: 'config.json'    },
  ];

  for (const c of checks) {
    const url = base.origin + c.path;
    try {
      const finding = await c.test(url, c.label);
      if (finding) results.push(finding);
      hooks.onZapLog?.(`  ✓ ${c.label}: ${finding ? finding.severity.toUpperCase() : 'OK'}`);
    } catch {
      hooks.onZapLog?.(`  - ${c.label}: error`);
    }
  }

  const severity = results.some(r => r.severity === 'critical') ? 'critical'
                 : results.some(r => r.severity === 'high')     ? 'high'
                 : results.some(r => r.severity === 'medium')   ? 'medium'
                 : results.length ? 'low' : 'ok';

  return {
    profile: 'zap-scan',
    target,
    severity,
    verdict: `[FALLBACK — ZAP no instalado] ${results.length} indicadores de vulnerabilidad encontrados.`,
    runner:  'fallback',
    mode,
    alerts:  results,
    stats: {
      total:    results.length,
      critical: results.filter(r => r.severity === 'critical').length,
      high:     results.filter(r => r.severity === 'high').length,
      medium:   results.filter(r => r.severity === 'medium').length,
      low:      results.filter(r => r.severity === 'low').length,
    },
    recommendations: [
      'Instala OWASP ZAP para un análisis DAST completo:',
      '  • Linux/Mac: https://www.zaproxy.org/download/',
      '  • Docker:    docker pull ghcr.io/zaproxy/zaproxy:stable',
      ...buildRecs(results),
    ],
  };
}

// ── HTTP helpers del fallback ─────────────────────────────────────────────────
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
        headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; FractiaZAP/3.0)' },
        rejectUnauthorized: false,
        timeout,
      };
      let body = '';
      const req = mod.request(options, res => {
        res.on('data', d => { body += d; });
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

async function checkHeadersBasic(url) {
  const res = await httpGet(url);
  if (res.status === 0) return null;
  const missing = [];
  if (!res.headers['content-security-policy']) missing.push('CSP');
  if (!res.headers['strict-transport-security']) missing.push('HSTS');
  if (!res.headers['x-frame-options']) missing.push('X-Frame-Options');
  if (missing.length >= 2) {
    return { type: 'finding', title: 'Security headers ausentes', severity: 'medium',
             description: `Faltan: ${missing.join(', ')}`, url };
  }
  return null;
}

async function checkLoginForm(url) {
  const res = await httpGet(url);
  if (res.status === 0 || res.status === 404) return null;
  const hasForm     = /<form/i.test(res.body);
  const hasPassword = /type=["']?password/i.test(res.body);
  const noCSRF      = hasForm && !/csrf|_token|nonce/i.test(res.body);
  if (hasPassword && noCSRF) {
    return { type: 'finding', title: 'Formulario de login sin token CSRF', severity: 'high',
             description: 'El formulario de login no incluye protección CSRF visible.', url };
  }
  return null;
}

async function checkApiEndpoint(url) {
  const res = await httpGet(url);
  if (res.status === 0 || res.status === 404) return null;
  const ct = res.headers['content-type'] || '';
  if (ct.includes('application/json') && res.status < 300) {
    return { type: 'finding', title: 'Endpoint API expuesto sin autenticación', severity: 'medium',
             description: `${url} responde con JSON sin credenciales.`, url };
  }
  return null;
}

async function checkSensitivePath(url, label) {
  const res = await httpGet(url);
  if (res.status === 200 || res.status === 301 || res.status === 302) {
    const sev = url.includes('.env') || url.includes('config') ? 'critical' : 'high';
    return { type: 'finding', title: `${label} accesible`, severity: sev,
             description: `${url} responde con HTTP ${res.status}.`, url };
  }
  return null;
}

// ── Recomendaciones ───────────────────────────────────────────────────────────
function buildRecs(alerts) {
  const recs = new Set();
  for (const a of alerts) {
    if (a.solution) recs.add(a.solution.replace(/<[^>]+>/g, '').trim());
    if (a.severity === 'critical') recs.add(`Prioridad MÁXIMA: corrige "${a.title}" antes de continuar.`);
    if (a.severity === 'high')     recs.add(`Alta prioridad: revisa "${a.title}".`);
  }
  if (!recs.size) recs.add('Sin alertas críticas. Considera un active scan periódico con ZAP.');
  return [...recs];
}
