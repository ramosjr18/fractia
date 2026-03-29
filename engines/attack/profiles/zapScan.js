/**
 * zapScan.js — OWASP ZAP Integration (Pilar C DAST)
 *
 * Tres modos de ejecución detectados automáticamente (en orden de preferencia):
 *
 *   1. ZAP GUI/Daemon corriendo — usa la REST API en localhost (recomendado)
 *      Si tienes ZAP abierto → ya funciona sin configuración adicional.
 *
 *   2. ZAP instalado localmente — lo arranca en modo daemon automáticamente
 *      (zaproxy / zap.sh detectado en paths comunes de Mac · Linux · Windows)
 *
 *   3. Docker disponible — usa ghcr.io/zaproxy/zaproxy:stable
 *
 *   4. Fallback built-in — reconocimiento HTTP propio + instrucciones de instalación
 *
 * API de diagnóstico exportada (usada por attackFlow.js para el setup interactivo):
 *   checkZapSetup()   → { mode, zapPath, apiPort, apiKey, needsApiKey }
 *   startZapDaemon()  → arranca zap.sh en background
 */
import { spawn, execSync, exec } from 'child_process';
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir, homedir } from 'os';
import path from 'path';
import http from 'http';
import https from 'https';
import { URL } from 'url';

export const meta = {
  id:          'zap-scan',
  name:        'OWASP ZAP Scan',
  description: 'DAST completo con OWASP ZAP — spider pasivo + alertas de vulnerabilidad',
  risk:        'medium',
  defaultOpts: {
    mode:     'baseline',  // 'baseline' | 'active'
    apiPort:  8080,
    apiKey:   '',          // vacío = sin API key (ZAP a veces la deshabilita)
    timeout:  120,
  },
};

// ── Severidad ZAP (riskcode) → Fractia ────────────────────────────────────────
const RISK_MAP = { '3': 'critical', '2': 'high', '1': 'medium', '0': 'low' };

// ── Rutas de instalación comunes de ZAP ───────────────────────────────────────
const ZAP_COMMON_PATHS = [
  // macOS — instalación via .dmg / app
  '/Applications/ZAP.app/Contents/Java/zap.sh',
  '/Applications/OWASP ZAP.app/Contents/Java/zap.sh',
  `${homedir()}/Applications/ZAP.app/Contents/Java/zap.sh`,
  // macOS — Homebrew
  '/opt/homebrew/bin/zap.sh',
  '/usr/local/bin/zap.sh',
  // Linux — paquete / descarga manual
  '/usr/bin/zaproxy',
  '/usr/local/bin/zaproxy',
  '/opt/zaproxy/zap.sh',
  `${homedir()}/ZAP/zap.sh`,
  `${homedir()}/zaproxy/zap.sh`,
  // Windows (por si acaso se ejecuta via WSL)
  '/mnt/c/Program Files/OWASP/Zed Attack Proxy/zap.bat',
];

// ── Detección de ZAP ──────────────────────────────────────────────────────────
function which(cmd) {
  try { execSync(`which ${cmd}`, { stdio: 'ignore' }); return true; } catch { return false; }
}

/**
 * Encuentra el ejecutable ZAP en el sistema.
 * Retorna la ruta o null si no se encuentra.
 */
export function findZapBinary() {
  // 1. En PATH
  for (const cmd of ['zaproxy', 'zap.sh', 'zap-cli']) {
    if (which(cmd)) return cmd;
  }
  // 2. Paths comunes
  for (const p of ZAP_COMMON_PATHS) {
    if (existsSync(p)) return p;
  }
  // 3. Glob: buscar en /Applications (macOS) y $HOME
  const searchDirs = ['/Applications', homedir()];
  for (const dir of searchDirs) {
    if (!existsSync(dir)) continue;
    try {
      const result = execSync(
        `find "${dir}" -name "zap.sh" -maxdepth 8 2>/dev/null | head -1`,
        { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }
      ).trim();
      if (result && existsSync(result)) return result;
    } catch {}
  }
  return null;
}

/**
 * Intenta conectarse a la API REST de ZAP.
 * Retorna { running, version, needsApiKey } o { running: false }
 */
export async function probeZapApi(port = 8080, apiKey = '') {
  return new Promise(resolve => {
    const keyParam = apiKey ? `?apikey=${encodeURIComponent(apiKey)}` : '';
    const options = {
      hostname: 'localhost',
      port,
      path:     `/JSON/core/view/version/${keyParam}`,
      method:   'GET',
      timeout:  3000,
    };
    const req = http.request(options, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          if (json.version) {
            resolve({ running: true, version: json.version, needsApiKey: false, port });
          } else if (json.code === 'unauthorized') {
            resolve({ running: true, version: null, needsApiKey: true, port });
          } else {
            resolve({ running: true, version: null, needsApiKey: false, port });
          }
        } catch {
          // Not JSON or unexpected response — ZAP is running but odd state
          if (res.statusCode === 403 || res.statusCode === 401) {
            resolve({ running: true, version: null, needsApiKey: true, port });
          } else {
            resolve({ running: true, version: null, needsApiKey: false, port });
          }
        }
      });
    });
    req.on('error', () => resolve({ running: false }));
    req.on('timeout', () => { req.destroy(); resolve({ running: false }); });
    req.end();
  });
}

/**
 * Diagnóstico completo. Retorna el estado de ZAP en el sistema.
 * Exportado para que attackFlow.js pueda usarlo en el setup interactivo.
 */
export async function checkZapSetup(opts = {}) {
  const apiPort = opts.apiPort || meta.defaultOpts.apiPort;
  const apiKey  = opts.apiKey  || meta.defaultOpts.apiKey;

  // 1. ¿ZAP API está corriendo?
  const probe = await probeZapApi(apiPort, apiKey);
  if (probe.running && !probe.needsApiKey) {
    return { mode: 'api', apiPort, apiKey, zapPath: null, version: probe.version };
  }
  if (probe.running && probe.needsApiKey) {
    return { mode: 'api-needs-key', apiPort, apiKey: null, zapPath: null };
  }

  // 2. ¿ZAP está instalado localmente?
  const zapPath = findZapBinary();
  if (zapPath) {
    // ¿Docker también disponible?
    const dockerOk = isDockerAvailable();
    return { mode: 'installed', zapPath, apiPort, apiKey: null, dockerAvailable: dockerOk };
  }

  // 3. ¿Docker disponible?
  if (isDockerAvailable()) {
    return { mode: 'docker', zapPath: null, apiPort, apiKey: null };
  }

  return { mode: 'none', zapPath: null, apiPort, apiKey: null };
}

function isDockerAvailable() {
  try { execSync('docker info', { stdio: 'ignore', timeout: 5000 }); return true; } catch { return false; }
}

// ── Arrancar ZAP en modo daemon ───────────────────────────────────────────────
/**
 * Arranca ZAP en modo daemon. Retorna cuando la API está lista (max 30s).
 */
export async function startZapDaemon(zapPath, port = 8080, apiKey = '') {
  const keyArgs = apiKey
    ? ['-config', `api.key=${apiKey}`]
    : ['-config', 'api.disablekey=true'];

  const args = [
    '-daemon',
    '-port', String(port),
    '-config', 'api.addrs.addr.name=.*',
    '-config', 'api.addrs.addr.regex=true',
    ...keyArgs,
  ];

  // Si es un .sh script, arrancarlo con sh
  const bin  = zapPath.endsWith('.sh') || zapPath.endsWith('.bat') ? zapPath : zapPath;
  const proc = spawn(bin, args, {
    stdio:    'ignore',
    detached: true,
  });
  proc.unref();

  // Esperar hasta 30s a que la API responda
  for (let i = 0; i < 30; i++) {
    await sleep(1000);
    const probe = await probeZapApi(port, apiKey);
    if (probe.running && !probe.needsApiKey) return { ok: true, pid: proc.pid };
  }
  return { ok: false };
}

// ── Runner principal ───────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const apiPort  = opts.apiPort  || meta.defaultOpts.apiPort;
  const apiKey   = opts.apiKey   || meta.defaultOpts.apiKey;
  const mode     = opts.mode     || meta.defaultOpts.mode;
  const timeout  = opts.timeout  || meta.defaultOpts.timeout;

  hooks.onPhase?.('init', 'Comprobando ZAP…');

  const setup = await checkZapSetup({ apiPort, apiKey });

  if (setup.mode === 'api') {
    hooks.onPhase?.('api', `ZAP API activa en localhost:${apiPort} (v${setup.version || '?'}) — escaneando ${target}`);
    return await runViaZapApi({ target, mode, timeout, apiPort, apiKey, hooks });
  }

  if (setup.mode === 'api-needs-key') {
    hooks.onPhase?.('error', 'ZAP API requiere API key — usa opts.apiKey o desactívala en ZAP → Opciones → API');
    return await fallbackScan({ target, hooks, mode, note: 'ZAP API activa pero requiere API key. Configúrala en Opciones → API de ZAP.' });
  }

  if (setup.mode === 'installed') {
    hooks.onPhase?.('daemon', `Iniciando ZAP daemon: ${setup.zapPath}`);
    const started = await startZapDaemon(setup.zapPath, apiPort, apiKey || '');
    if (started.ok) {
      hooks.onPhase?.('api', `ZAP daemon listo en localhost:${apiPort}`);
      return await runViaZapApi({ target, mode, timeout, apiPort, apiKey: apiKey || '', hooks });
    }

    // El daemon no respondió en 30s. Puede ser porque ZAP GUI ya estaba corriendo
    // en el mismo puerto y bloqueó el arranque de una segunda instancia.
    // Reintentamos la API — es probable que ZAP GUI ya esté disponible ahora.
    hooks.onPhase?.('retry', 'Re-comprobando API de ZAP (GUI puede estar ya activo)…');
    const retryProbe = await probeZapApi(apiPort, apiKey || '');
    if (retryProbe.running && !retryProbe.needsApiKey) {
      hooks.onPhase?.('api', `ZAP API disponible en localhost:${apiPort} (v${retryProbe.version || '?'})`);
      return await runViaZapApi({ target, mode, timeout, apiPort, apiKey: apiKey || '', hooks });
    }
    if (retryProbe.running && retryProbe.needsApiKey) {
      return await fallbackScan({
        target, hooks, mode,
        note: 'ZAP está corriendo pero requiere API key. Ve a ZAP → Herramientas → Opciones → API y desactiva la clave, luego vuelve a intentarlo.',
      });
    }

    hooks.onPhase?.('error', 'ZAP no respondió tras el intento de arranque');
    return await fallbackScan({ target, hooks, mode });
  }

  if (setup.mode === 'docker') {
    return await runWithDocker({ target, mode, timeout, hooks });
  }

  // Sin ZAP de ningún tipo
  return await fallbackScan({ target, hooks, mode });
}

// ── ZAP REST API runner ───────────────────────────────────────────────────────
async function runViaZapApi({ target, mode, timeout, apiPort, apiKey, hooks }) {
  const key = apiKey ? `&apikey=${encodeURIComponent(apiKey)}` : '';

  const zapGet = (path) => zapApiGet(`localhost`, apiPort, path + (path.includes('?') ? key.replace('&','&') : (key ? '?' + key.slice(1) : '')));

  hooks.onPhase?.('newSession', 'Iniciando nueva sesión ZAP…');
  await zapGet('/JSON/core/action/newSession/');

  // Habilitar escáneres pasivos
  await zapGet('/JSON/pscan/action/enableAllScanners/');
  await zapGet('/JSON/pscan/action/setEnabled/?enabled=true');

  // Spider scan
  hooks.onPhase?.('spider', `Spider escaneando ${target}…`);
  const spiderRes = await zapGet(`/JSON/spider/action/scan/?url=${encodeURIComponent(target)}&maxChildren=10&recurse=true`);
  const scanId    = spiderRes?.scan;

  if (scanId !== undefined) {
    // Esperar a que el spider complete
    const deadline = Date.now() + Math.min(timeout * 500, 60000); // max 60s para spider
    while (Date.now() < deadline) {
      await sleep(2000);
      const status = await zapGet(`/JSON/spider/view/status/?scanId=${scanId}`);
      const pct = parseInt(status?.status ?? 0, 10);
      hooks.onZapLog?.(`  Spider: ${pct}% completado`);
      if (pct >= 100) break;
    }
  }

  // Si modo active: lanzar active scan
  if (mode === 'active') {
    hooks.onPhase?.('activeScan', 'Active scan en curso…');
    const asRes  = await zapGet(`/JSON/ascan/action/scan/?url=${encodeURIComponent(target)}&recurse=true&inScopeOnly=false`);
    const asId   = asRes?.scan;
    if (asId !== undefined) {
      const deadline = Date.now() + timeout * 1000;
      while (Date.now() < deadline) {
        await sleep(3000);
        const status = await zapGet(`/JSON/ascan/view/status/?scanId=${asId}`);
        const pct = parseInt(status?.status ?? 0, 10);
        hooks.onZapLog?.(`  Active scan: ${pct}% completado`);
        if (pct >= 100) break;
      }
    }
  }

  // Esperar a que termine el passive scanner
  hooks.onPhase?.('passiveScan', 'Esperando passive scan…');
  const pDeadline = Date.now() + 30000;
  while (Date.now() < pDeadline) {
    const remaining = await zapGet('/JSON/pscan/view/recordsToScan/');
    const n = parseInt(remaining?.recordsToScan ?? 0, 10);
    if (n === 0) break;
    hooks.onZapLog?.(`  Passive scan: ${n} registros pendientes`);
    await sleep(2000);
  }

  // Obtener alertas
  hooks.onPhase?.('alerts', 'Recogiendo alertas…');
  const alertsRes = await zapGet(`/JSON/core/view/alerts/?baseurl=${encodeURIComponent(target)}&start=0&count=500`);
  const rawAlerts = alertsRes?.alerts || [];

  return buildResultFromApiAlerts(rawAlerts, target, mode, 'api');
}

/**
 * Petición GET a la ZAP API. Retorna JSON parsed o null.
 */
function zapApiGet(host, port, path) {
  return new Promise(resolve => {
    const options = {
      hostname: host,
      port,
      path,
      method: 'GET',
      timeout: 10000,
      headers: { 'Accept': 'application/json' },
    };
    const req = http.request(options, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ── Docker runner ─────────────────────────────────────────────────────────────
async function runWithDocker({ target, mode, timeout, hooks }) {
  hooks.onPhase?.('docker', 'Iniciando ZAP via Docker…');

  const reportDir  = path.join(tmpdir(), `fractia-zap-${Date.now()}`);
  mkdirSync(reportDir, { recursive: true });
  const zapScript  = mode === 'active' ? 'zap-full-scan.py' : 'zap-baseline.py';

  const args = [
    'run', '--rm',
    '-v', `${reportDir}:/zap/wrk:rw`,
    'ghcr.io/zaproxy/zaproxy:stable',
    zapScript,
    '-t', target,
    '-J', 'report.json',
    '-I',
    '-T', String(timeout),
  ];

  try {
    await spawnAndStream('docker', args, hooks, (timeout + 60) * 1000);
  } catch (err) {
    hooks.onZapLog?.(`[docker error] ${err.message}`);
    return await fallbackScan({ target, hooks, mode, note: `Docker ZAP falló: ${err.message}` });
  }

  const reportPath = path.join(reportDir, 'report.json');
  if (!existsSync(reportPath)) {
    return await fallbackScan({ target, hooks, mode, note: 'Docker no generó el reporte JSON' });
  }

  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    unlinkSync(reportPath);
    return parseZapJsonReport(raw, target, mode, 'docker');
  } catch (err) {
    return await fallbackScan({ target, hooks, mode, note: `Error leyendo reporte: ${err.message}` });
  }
}

// ── Construir resultado desde alertas de la API REST ──────────────────────────
function buildResultFromApiAlerts(rawAlerts, target, mode, runner) {
  const alerts = rawAlerts.map(a => ({
    type:        'finding',
    title:       a.name || a.alert || 'ZAP Alert',
    severity:    RISK_MAP[String(a.riskcode)] || 'low',
    description: stripHtml(a.desc || a.description || ''),
    solution:    stripHtml(a.solution || ''),
    reference:   stripHtml(a.reference || ''),
    url:         a.instances?.[0]?.uri || a.url || target,
    param:       a.instances?.[0]?.param || a.param || '',
    evidence:    a.instances?.[0]?.evidence || a.evidence || '',
    pluginId:    a.pluginid || a.pluginId || '',
    cweId:       a.cweid   || a.cweId    || '',
    wascId:      a.wascid  || a.wascId   || '',
    count:       parseInt(a.count ?? 1, 10),
    confidence:  a.confidence || '',
  }));

  return buildFinalResult(alerts, target, mode, runner);
}

// ── Construir resultado desde reporte JSON (CLI/Docker) ───────────────────────
function parseZapJsonReport(raw, target, mode, runner) {
  const alerts = [];
  const sites = raw.site || raw.sites || (raw.alerts ? [raw] : []);

  for (const site of (Array.isArray(sites) ? sites : [sites])) {
    for (const a of (site.alerts || [])) {
      const risk = parseInt(a.riskcode ?? a.risk ?? 0, 10);
      alerts.push({
        type:        'finding',
        title:       a.name || a.alert || 'ZAP Alert',
        severity:    RISK_MAP[String(risk)] || 'low',
        description: stripHtml(a.desc || ''),
        solution:    stripHtml(a.solution || ''),
        reference:   stripHtml(a.reference || ''),
        url:         a.instances?.[0]?.uri || a.url || target,
        param:       a.instances?.[0]?.param || '',
        evidence:    a.instances?.[0]?.evidence || '',
        pluginId:    a.pluginid || '',
        cweId:       a.cweid   || '',
        wascId:      a.wascid  || '',
        count:       parseInt(a.count ?? 1, 10),
      });
    }
  }

  return buildFinalResult(alerts, target, mode, runner);
}

// ── Nombres descriptivos de runner ────────────────────────────────────────────
const RUNNER_LABELS = {
  api:      'ZAP API (localhost)',
  docker:   'ZAP Docker',
  local:    'ZAP CLI (local)',
  fallback: 'Fractia built-in (ZAP no disponible)',
};

// ── Resultado final unificado ─────────────────────────────────────────────────
function buildFinalResult(alerts, target, mode, runner) {
  alerts.sort((a, b) => {
    const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
    return (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4);
  });

  const critical = alerts.filter(a => a.severity === 'critical');
  const high     = alerts.filter(a => a.severity === 'high');
  const medium   = alerts.filter(a => a.severity === 'medium');
  const low      = alerts.filter(a => a.severity === 'low');

  // Agrupar alertas low por tipo para el veredicto
  const lowTypes = [...new Set(low.map(a => a.title))];

  let severity, verdict;
  if (critical.length) {
    severity = 'critical';
    verdict  = `CRÍTICO — ${critical.length} vulnerabilidades críticas encontradas por ZAP.`;
  } else if (high.length) {
    severity = 'high';
    verdict  = `ALTO — ${high.length} alertas de alto riesgo en el escaneo ZAP.`;
  } else if (medium.length) {
    severity = 'medium';
    verdict  = `MEDIO — ${medium.length} alertas de riesgo moderado. Sin vulnerabilidades explotables directas.`;
  } else if (low.length) {
    severity = 'low';
    const topIssues = lowTypes.slice(0, 2).join(', ');
    verdict  = `BAJO — ${low.length} alertas informativas (${lowTypes.length} tipos). Principal: ${topIssues}.`;
  } else {
    severity = 'ok';
    verdict  = 'SIN HALLAZGOS — ZAP no encontró vulnerabilidades en el escaneo.';
  }

  return {
    profile: 'zap-scan',
    target,
    severity,
    verdict,
    runner:       RUNNER_LABELS[runner] || runner,
    runnerRaw:    runner,
    mode,
    alerts,
    stats: {
      total:    alerts.length,
      critical: critical.length,
      high:     high.length,
      medium:   medium.length,
      low:      low.length,
      lowTypes: lowTypes.length,
    },
    recommendations: buildRecs(alerts),
  };
}

// ── Fallback built-in ─────────────────────────────────────────────────────────
async function fallbackScan({ target, hooks, mode, note }) {
  hooks.onPhase?.('fallback', 'Ejecutando reconocimiento HTTP propio…');

  const base     = new URL(target);
  const results  = [];
  const checks   = [
    { path: '/',             fn: checkHeadersBasic,  label: 'Security headers' },
    { path: '/login',        fn: checkLoginForm,     label: 'Login form'       },
    { path: '/api',          fn: checkApiEndpoint,   label: 'API exposure'     },
    { path: '/admin',        fn: checkSensitivePath, label: 'Admin panel'      },
    { path: '/.env',         fn: checkSensitivePath, label: '.env'             },
    { path: '/config.json',  fn: checkSensitivePath, label: 'config.json'      },
    { path: '/.git/HEAD',    fn: checkSensitivePath, label: '.git/HEAD'        },
    { path: '/graphql',      fn: checkSensitivePath, label: 'GraphQL'          },
  ];

  for (const c of checks) {
    try {
      const finding = await c.fn(base.origin + c.path, c.label);
      if (finding) results.push(finding);
      hooks.onZapLog?.(`  ${finding ? '✖ ' + finding.severity.toUpperCase() : '✓ OK'} — ${c.label}`);
    } catch {}
  }

  const severity = results.some(r => r.severity === 'critical') ? 'critical'
                 : results.some(r => r.severity === 'high')     ? 'high'
                 : results.some(r => r.severity === 'medium')   ? 'medium'
                 : results.length ? 'low' : 'ok';

  const recs = [
    'Para análisis DAST completo, conecta ZAP:',
    '  1. Abre OWASP ZAP (GUI o daemon)',
    '  2. Ve a ZAP → Herramientas → Opciones → API y anota la API key',
    '  3. Corre fractia con --zap-api-key TU_KEY (o desactiva la key en ZAP)',
    ...buildRecs(results),
  ];
  if (note) recs.unshift(note);

  return {
    profile:    'zap-scan',
    target,
    severity,
    verdict:    `[FALLBACK] ${results.length} indicadores de vulnerabilidad encontrados.`,
    runner:     'fallback',
    mode,
    alerts:     results,
    stats: {
      total:    results.length,
      critical: results.filter(r => r.severity === 'critical').length,
      high:     results.filter(r => r.severity === 'high').length,
      medium:   results.filter(r => r.severity === 'medium').length,
      low:      results.filter(r => r.severity === 'low').length,
    },
    recommendations: recs,
  };
}

// ── Spawn helper ──────────────────────────────────────────────────────────────
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
      chunk.toString().split('\n').forEach(l => {
        const c = l.trim();
        if (c) hooks.onZapLog?.(`[err] ${c}`);
      });
    });

    const timer = setTimeout(() => { proc.kill('SIGTERM'); reject(new Error(`ZAP timeout`)); }, timeoutMs);
    proc.on('close', code => {
      clearTimeout(timer);
      if (code === 0 || code === 2) resolve(code);
      else reject(new Error(`ZAP salió con código ${code}`));
    });
    proc.on('error', err => { clearTimeout(timer); reject(err); });
  });
}

// ── HTTP helpers del fallback ─────────────────────────────────────────────────
function httpGet(url, timeout = 6000) {
  return new Promise(resolve => {
    try {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
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
        res.on('data', d => { if (body.length < 8192) body += d; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '' }); });
      req.end();
    } catch { resolve({ status: 0, headers: {}, body: '' }); }
  });
}

async function checkHeadersBasic(url) {
  const res = await httpGet(url);
  if (res.status === 0) return null;
  const missing = [];
  if (!res.headers['content-security-policy']) missing.push('CSP');
  if (!res.headers['strict-transport-security']) missing.push('HSTS');
  if (!res.headers['x-frame-options']) missing.push('X-Frame-Options');
  if (missing.length >= 2) return { type: 'finding', title: 'Security headers ausentes', severity: 'medium', description: `Faltan: ${missing.join(', ')}`, url };
  return null;
}
async function checkLoginForm(url) {
  const res = await httpGet(url);
  if (res.status === 0 || res.status === 404) return null;
  const hasForm = /<form/i.test(res.body);
  const hasPass = /type=["']?password/i.test(res.body);
  const noCSRF  = hasForm && !/csrf|_token|nonce/i.test(res.body);
  if (hasPass && noCSRF) return { type: 'finding', title: 'Formulario de login sin CSRF', severity: 'high', description: 'Login form sin token CSRF visible.', url };
  return null;
}
async function checkApiEndpoint(url) {
  const res = await httpGet(url);
  if (res.status === 0 || res.status === 404) return null;
  const ct = res.headers['content-type'] || '';
  if (ct.includes('application/json') && res.status < 300) return { type: 'finding', title: 'Endpoint API expuesto', severity: 'medium', description: `${url} responde JSON sin credenciales.`, url };
  return null;
}
async function checkSensitivePath(url, label) {
  const res = await httpGet(url);
  if (res.status === 200 || res.status === 301 || res.status === 302) {
    const sev = url.includes('.env') || url.includes('.git') || url.includes('config') ? 'critical' : 'high';
    return { type: 'finding', title: `${label} accesible`, severity: sev, description: `${url} responde HTTP ${res.status}.`, url };
  }
  return null;
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function stripHtml(str) {
  return str.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function buildRecs(alerts) {
  const recs = new Set();
  for (const a of alerts) {
    if (a.solution) recs.add(a.solution.slice(0, 200));
    if (a.severity === 'critical') recs.add(`Prioridad MÁXIMA: "${a.title}"`);
    else if (a.severity === 'high') recs.add(`Alta prioridad: "${a.title}"`);
  }
  if (!recs.size) recs.add('Sin alertas críticas. Programa escaneos ZAP periódicos.');
  return [...recs];
}
