/**
 * Form Flood — Pilar C DAST: ataques contra formularios HTML
 *
 * Modos:
 *   flood      — envío masivo para validar rate limiting
 *   user-enum  — detectar si el servidor revela si un email/usuario existe
 *   stuffing   — credential stuffing con CSRF + cookies
 *   spam       — flood de contenido en formularios de contacto/comentarios
 *   inject     — payloads XSS + SQLi en campos del formulario
 *
 * Flujo común:
 *   1. GET de la página → extraer form (action, method, fields, CSRF token)
 *   2. Mantener cookies de sesión entre GET y POST
 *   3. Enviar con application/x-www-form-urlencoded
 */
import { URL } from 'url';
import http from 'http';
import https from 'https';

export const meta = {
  id:          'form-flood',
  name:        'Form Flood',
  description: 'Ataques contra formularios HTML: flood, user-enum, stuffing, spam, inject',
  risk:        'medium',
  modes:       ['flood', 'user-enum', 'stuffing', 'spam', 'inject'],
  defaultOpts: {
    mode:        'flood',
    requests:    200,
    concurrency: 10,
    duration:    30,
  },
};

// ── Injection payloads ────────────────────────────────────────────────────────
const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "';alert(1)//",
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '{{7*7}}',                         // template injection
  '${7*7}',
  '<iframe src="javascript:alert(1)">',
  '"><img src=x onerror=alert(document.cookie)>',
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "admin'--",
  "' OR 1=1--",
  "'; DROP TABLE users--",
  "' UNION SELECT null,null--",
  "1' AND SLEEP(3)--",
  "1; SELECT pg_sleep(3)--",
  "' OR ''='",
  "\" OR \"\"=\"",
];

// ── Fake data pools ───────────────────────────────────────────────────────────
const EMAILS    = ['test@test.com','admin@test.com','user@example.com','hello@test.com','demo@test.com','root@test.com','noreply@test.com','info@test.com'];
const PASSWORDS = ['password','123456','admin','test123','qwerty','letmein','welcome1','pass123','secret','abc123'];
const NAMES     = ['Test User','John Doe','Jane Smith','Admin User','Demo Account','Random Person','Fake Name','Bot User'];
const MESSAGES  = [
  'Hello, I am interested in your services.',
  'Please contact me regarding your offer.',
  'Test message from automated system.',
  'I would like more information.',
  'Great website! Keep it up.',
  'Can you send me a quote?',
];

// ── Main runner ───────────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  const { mode, requests, concurrency, duration, formIndex = 0 } = { ...meta.defaultOpts, ...opts };

  // Step 1: Discover the form
  hooks.onPhase?.('discover', `GET ${target}`);
  const discovery = await discoverForm(target, formIndex);

  if (!discovery.form) {
    return {
      profile: 'form-flood', target, mode,
      severity: 'low',
      verdict: `No se encontró ningún formulario en ${target}`,
      stats: { formsFound: discovery.formsFound },
      recommendations: ['Verifica la URL — puede requerir autenticación o ser una SPA.'],
    };
  }

  hooks.onFormFound?.(discovery);

  // Step 2: Run the selected mode
  switch (mode) {
    case 'flood':    return runFlood({ target, discovery, requests, concurrency, duration, hooks });
    case 'user-enum':return runUserEnum({ target, discovery, requests: Math.min(requests, 50), concurrency: 3, duration, hooks });
    case 'stuffing': return runStuffing({ target, discovery, requests, concurrency, duration, hooks });
    case 'spam':     return runSpam({ target, discovery, requests, concurrency, duration, hooks });
    case 'inject':   return runInject({ target, discovery, hooks });
    default: throw new Error(`Modo desconocido: ${mode}. Opciones: ${meta.modes.join(', ')}`);
  }
}

// ── Mode: FLOOD ───────────────────────────────────────────────────────────────
async function runFlood({ target, discovery, requests, concurrency, duration, hooks }) {
  const stats    = makeStats();
  const start    = Date.now();
  let   stopped  = false;
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  hooks.onStart?.({ mode: 'flood', requests, target: discovery.actionUrl });

  for (let i = 0; i < requests && !stopped; i += concurrency) {
    const batch = Math.min(concurrency, requests - i);
    await Promise.all(Array.from({ length: batch }, async (_, j) => {
      if (stopped) return;
      const t0   = Date.now();
      // Re-fetch CSRF token each batch if present
      const disc = discovery.csrfField ? await discoverForm(target, discovery.formIndex) : discovery;
      const body = buildBody(disc.form, disc.csrfValue, {
        email: EMAILS[(i + j) % EMAILS.length],
        password: PASSWORDS[(i + j) % PASSWORDS.length],
        name: NAMES[(i + j) % NAMES.length],
        message: MESSAGES[(i + j) % MESSAGES.length],
      });
      const res = await submitForm(disc, body);
      recordResult(stats, res, Date.now() - t0);
      hooks.onRequest?.({ sent: stats.sent, status: res.status, ms: Date.now() - t0, blocked: stats.blocked });
    }));
    hooks.onBatch?.({ done: Math.min(i + batch, requests), total: requests, stats });
  }

  clearTimeout(hardStop);
  return buildVerdict('flood', target, stats, discovery);
}

// ── Mode: USER ENUM ───────────────────────────────────────────────────────────
async function runUserEnum({ target, discovery, requests, concurrency, duration, hooks }) {
  const results  = [];
  const start    = Date.now();
  let   stopped  = false;
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  // Distinct email list: some real-looking, some fake
  const testEmails = [
    'admin@' + new URL(target).hostname,
    'daniel@' + new URL(target).hostname,
    'user@' + new URL(target).hostname,
    'notexist_zzz_xyz@' + new URL(target).hostname,
    'test_fake_9999@example.com',
    'support@' + new URL(target).hostname,
    'info@' + new URL(target).hostname,
    'hello@' + new URL(target).hostname,
  ].slice(0, requests);

  hooks.onStart?.({ mode: 'user-enum', emails: testEmails.length, target: discovery.actionUrl });

  for (const email of testEmails) {
    if (stopped) break;
    const disc = discovery.csrfField ? await discoverForm(target, discovery.formIndex) : discovery;
    const body = buildBody(disc.form, disc.csrfValue, { email, password: 'wrongpassword_xyz' });
    const t0   = Date.now();
    const res  = await submitForm(disc, body);
    const ms   = Date.now() - t0;

    results.push({ email, status: res.status, ms, bodySnippet: res.body?.slice(0, 200) });
    hooks.onEnumResult?.({ email, status: res.status, ms, body: res.body?.slice(0, 150) });
  }

  clearTimeout(hardStop);

  // Analyse: do responses differ between emails?
  const statuses  = [...new Set(results.map(r => r.status))];
  const bodyDiffs = detectBodyDifferences(results);

  let verdict, severity;
  if (bodyDiffs.leaksExistence) {
    verdict  = `VULNERABLE — el servidor revela si un email existe: "${bodyDiffs.hint}"`;
    severity = 'high';
  } else if (statuses.length > 1) {
    verdict  = 'MODERADO — diferentes códigos HTTP según el email (posible enumeración).';
    severity = 'medium';
  } else {
    verdict  = 'RESILIENTE — respuestas uniformes, no se puede enumerar usuarios.';
    severity = 'ok';
  }

  return {
    profile: 'form-flood', target, mode: 'user-enum', severity, verdict,
    stats: { tested: results.length, statuses, bodyLeaks: bodyDiffs.leaksExistence },
    findings: results,
    recommendations: severity !== 'ok' ? [
      'Usa un mensaje genérico para emails existentes y no existentes: "Si el email está registrado, recibirás un enlace."',
      'Normaliza los tiempos de respuesta (constant-time comparison) para evitar timing attacks.',
    ] : ['Las respuestas son uniformes. Buen resultado.'],
  };
}

// ── Mode: STUFFING (form con CSRF) ────────────────────────────────────────────
async function runStuffing({ target, discovery, requests, concurrency, duration, hooks }) {
  const stats    = makeStats();
  const start    = Date.now();
  let   stopped  = false;
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  hooks.onStart?.({ mode: 'stuffing', requests, target: discovery.actionUrl });

  for (let i = 0; i < requests && !stopped; i += concurrency) {
    const batch = Math.min(concurrency, requests - i);
    await Promise.all(Array.from({ length: batch }, async (_, j) => {
      if (stopped) return;
      // Always re-fetch CSRF token (tokens are single-use in most frameworks)
      const disc = await discoverForm(target, discovery.formIndex);
      const body = buildBody(disc.form, disc.csrfValue, {
        email:    EMAILS[(i + j) % EMAILS.length],
        password: PASSWORDS[(i + j) % PASSWORDS.length],
      });
      const t0  = Date.now();
      const res = await submitForm(disc, body);
      recordResult(stats, res, Date.now() - t0);
      hooks.onRequest?.({ sent: stats.sent, status: res.status, ms: Date.now() - t0, blocked: stats.blocked });
    }));
    hooks.onBatch?.({ done: Math.min(i + batch, requests), total: requests, stats });
  }

  clearTimeout(hardStop);
  return buildVerdict('stuffing', target, stats, discovery);
}

// ── Mode: SPAM ────────────────────────────────────────────────────────────────
async function runSpam({ target, discovery, requests, concurrency, duration, hooks }) {
  const stats    = makeStats();
  let   stopped  = false;
  const hardStop = setTimeout(() => { stopped = true; }, duration * 1000);

  hooks.onStart?.({ mode: 'spam', requests, target: discovery.actionUrl });

  for (let i = 0; i < requests && !stopped; i += concurrency) {
    const batch = Math.min(concurrency, requests - i);
    await Promise.all(Array.from({ length: batch }, async (_, j) => {
      if (stopped) return;
      const disc = discovery.csrfField ? await discoverForm(target, discovery.formIndex) : discovery;
      const body = buildBody(disc.form, disc.csrfValue, {
        name:    NAMES[(i + j) % NAMES.length],
        email:   EMAILS[(i + j) % EMAILS.length],
        message: MESSAGES[(i + j) % MESSAGES.length] + ` [${i + j}]`,
        subject: `Test message ${i + j}`,
        comment: MESSAGES[(i + j) % MESSAGES.length],
      });
      const t0  = Date.now();
      const res = await submitForm(disc, body);
      recordResult(stats, res, Date.now() - t0);
      hooks.onRequest?.({ sent: stats.sent, status: res.status, ms: Date.now() - t0, blocked: stats.blocked });
    }));
    hooks.onBatch?.({ done: Math.min(i + batch, requests), total: requests, stats });
  }

  clearTimeout(hardStop);
  return buildVerdict('spam', target, stats, discovery);
}

// ── Mode: INJECT ──────────────────────────────────────────────────────────────
async function runInject({ target, discovery, hooks }) {
  const results  = [];
  const allPayloads = [
    ...XSS_PAYLOADS.map(p => ({ type: 'XSS',  payload: p })),
    ...SQLI_PAYLOADS.map(p => ({ type: 'SQLi', payload: p })),
  ];

  hooks.onStart?.({ mode: 'inject', payloads: allPayloads.length, target: discovery.actionUrl });

  const fields = discovery.form.filter(f => ['text','email','search','textarea','password','hidden'].includes(f.type) && !f.isToken);

  for (const { type, payload } of allPayloads) {
    for (const field of fields) {
      const disc = discovery.csrfField ? await discoverForm(target, discovery.formIndex) : discovery;
      // Build body: inject into this field, safe values in others
      const overrides = {};
      overrides[field.name] = payload;
      const body = buildBody(disc.form, disc.csrfValue, overrides, { usePayloadKey: field.name });
      const t0   = Date.now();
      const res  = await submitForm(disc, body);
      const ms   = Date.now() - t0;

      const reflected  = res.body ? res.body.includes(payload) : false;
      const sqlError   = type === 'SQLi' && res.body ? detectSQLError(res.body) : false;
      const timingHit  = type === 'SQLi' && ms > 2800;

      const finding = {
        type, field: field.name, payload,
        status: res.status, ms, reflected, sqlError, timingHit,
        severity: reflected || sqlError || timingHit ? 'high' : 'ok',
      };
      results.push(finding);
      hooks.onInjectResult?.({ ...finding, bodySnippet: res.body?.slice(0, 100) });
    }
  }

  // Summary
  const vulns     = results.filter(r => r.severity === 'high');
  const xssHits   = vulns.filter(r => r.type === 'XSS' && r.reflected);
  const sqliHits  = vulns.filter(r => r.type === 'SQLi' && (r.sqlError || r.timingHit));

  let verdict, severity;
  if (xssHits.length > 0 || sqliHits.length > 0) {
    const parts = [];
    if (xssHits.length)  parts.push(`XSS reflejado en campo "${xssHits[0].field}"`);
    if (sqliHits.length) parts.push(`SQLi detectado en campo "${sqliHits[0].field}"`);
    verdict  = `VULNERABLE — ${parts.join(' · ')}`;
    severity = 'critical';
  } else if (results.some(r => r.status >= 500)) {
    verdict  = 'REVISAR — el servidor devuelve 5xx ante ciertos payloads (posible error no controlado).';
    severity = 'high';
  } else {
    verdict  = `RESILIENTE — ${allPayloads.length} payloads probados, ninguno reflejado ni errores SQL.`;
    severity = 'ok';
  }

  return {
    profile: 'form-flood', target, mode: 'inject', severity, verdict,
    stats: { payloadsTested: results.length, fieldsProbed: fields.length, vulnerabilities: vulns.length },
    findings: vulns.length > 0 ? vulns : [],
    allResults: results,
    recommendations: buildInjectRecs(xssHits, sqliHits, severity),
  };
}

// ── Form discovery ────────────────────────────────────────────────────────────
async function discoverForm(pageUrl, formIndex = 0) {
  const { html, cookies, finalUrl } = await fetchPage(pageUrl);
  const forms = parseFormsFromHTML(html, finalUrl || pageUrl);

  if (!forms.length) return { form: null, formsFound: 0 };

  const form      = forms[Math.min(formIndex, forms.length - 1)];
  const csrfField = form.find(f => f.isToken);
  const csrfValue = csrfField?.value || '';

  return {
    form,
    formIndex: Math.min(formIndex, forms.length - 1),
    formsFound: forms.length,
    actionUrl:  form._action,
    method:     form._method,
    csrfField:  csrfField?.name || null,
    csrfValue,
    cookies,
    pageUrl,
  };
}

async function fetchPage(url) {
  return new Promise((resolve) => {
    const parsed   = new URL(url);
    const mod      = parsed.protocol === 'https:' ? https : http;
    const options  = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'GET',
      headers:  { 'User-Agent': 'Mozilla/5.0 (compatible; FractiaBot/3.0)', Accept: 'text/html' },
      rejectUnauthorized: false,
      timeout: 8000,
    };
    const chunks = [];
    const cookies = [];
    const req = mod.request(options, res => {
      // Collect Set-Cookie headers
      const setCookie = res.headers['set-cookie'] || [];
      for (const c of setCookie) cookies.push(c.split(';')[0]);
      res.on('data', d => chunks.push(d));
      res.on('end', () => resolve({
        html: Buffer.concat(chunks).toString('utf8'),
        cookies,
        finalUrl: res.headers['location'] || url,
        status: res.statusCode,
      }));
    });
    req.on('error', () => resolve({ html: '', cookies: [], finalUrl: url }));
    req.on('timeout', () => { req.destroy(); resolve({ html: '', cookies: [], finalUrl: url }); });
    req.end();
  });
}

function parseFormsFromHTML(html, baseUrl) {
  const forms  = [];
  const base   = new URL(baseUrl);

  // Match all <form> blocks
  const formRe = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let   fMatch;

  while ((fMatch = formRe.exec(html)) !== null) {
    const attrs  = fMatch[1];
    const inner  = fMatch[2];

    const action = extractAttr(attrs, 'action') || baseUrl;
    const method = (extractAttr(attrs, 'method') || 'POST').toUpperCase();

    // Resolve relative action URL
    let actionUrl;
    try {
      actionUrl = new URL(action, baseUrl).href;
    } catch {
      actionUrl = baseUrl;
    }

    const fields = [];

    // <input ...>
    const inputRe = /<input([^>]*)>/gi;
    let iMatch;
    while ((iMatch = inputRe.exec(inner)) !== null) {
      const a      = iMatch[1];
      const type   = (extractAttr(a, 'type') || 'text').toLowerCase();
      const name   = extractAttr(a, 'name') || '';
      const value  = extractAttr(a, 'value') || '';
      if (!name) continue;
      fields.push({
        name, type, value,
        isToken: isCSRFField(name, type, value),
      });
    }

    // <textarea ...>
    const textareaRe = /<textarea([^>]*)>([^<]*)<\/textarea>/gi;
    let taMatch;
    while ((taMatch = textareaRe.exec(inner)) !== null) {
      const a    = taMatch[1];
      const name = extractAttr(a, 'name') || '';
      if (!name) continue;
      fields.push({ name, type: 'textarea', value: '', isToken: false });
    }

    // <select ...>
    const selectRe = /<select([^>]*)>/gi;
    let sMatch;
    while ((sMatch = selectRe.exec(inner)) !== null) {
      const name = extractAttr(sMatch[1], 'name') || '';
      if (!name) continue;
      fields.push({ name, type: 'select', value: '', isToken: false });
    }

    if (fields.length > 0) {
      fields._action = actionUrl;
      fields._method = method;
      forms.push(fields);
    }
  }

  return forms;
}

// ── Form submission ───────────────────────────────────────────────────────────
async function submitForm(discovery, body) {
  const { actionUrl, method, cookies } = discovery;
  return new Promise((resolve) => {
    const parsed  = new URL(actionUrl);
    const mod     = parsed.protocol === 'https:' ? https : http;
    const encoded = encodeBody(body);

    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   method || 'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(encoded),
        'User-Agent':     'Mozilla/5.0 (compatible; FractiaBot/3.0)',
        'Cookie':         cookies?.join('; ') || '',
        'Accept':         'text/html,application/xhtml+xml',
        'Referer':        discovery.pageUrl || actionUrl,
      },
      rejectUnauthorized: false,
      timeout: 8000,
    };

    const chunks = [];
    const req = mod.request(options, res => {
      res.on('data', d => chunks.push(d));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: 'TIMEOUT' }); });
    req.write(encoded);
    req.end();
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function buildBody(form, csrfValue, overrides = {}, opts = {}) {
  const body = {};
  for (const field of form) {
    if (Array.isArray(field)) continue;   // skip _action/_method
    if (field.isToken) {
      body[field.name] = csrfValue || field.value;
    } else if (overrides[field.name] !== undefined) {
      body[field.name] = overrides[field.name];
    } else {
      // Smart defaults by field name
      const n = field.name.toLowerCase();
      if      (/email/i.test(n))                   body[field.name] = overrides.email    || EMAILS[0];
      else if (/pass/i.test(n))                    body[field.name] = overrides.password || PASSWORDS[0];
      else if (/name|nombre/i.test(n))             body[field.name] = overrides.name     || NAMES[0];
      else if (/message|mensaje|comment/i.test(n)) body[field.name] = overrides.message  || MESSAGES[0];
      else if (/subject|asunto/i.test(n))          body[field.name] = overrides.subject  || 'Test';
      else if (field.type === 'hidden')             body[field.name] = field.value;
      else                                          body[field.name] = field.value || 'test';
    }
  }
  return body;
}

function encodeBody(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`)
    .join('&');
}

function makeStats() {
  return { sent: 0, ok: 0, blocked: 0, errors: 0, statuses: {}, responseTimesMs: [] };
}

function recordResult(stats, res, ms) {
  stats.sent++;
  stats.responseTimesMs.push(ms);
  stats.statuses[res.status] = (stats.statuses[res.status] || 0) + 1;
  if (res.status === 429 || res.status === 403) stats.blocked++;
  else if (res.status === 0) stats.errors++;
  else stats.ok++;
}

function buildVerdict(mode, target, stats, discovery) {
  const ratio = stats.sent > 0 ? stats.blocked / stats.sent : 0;
  const avg   = stats.responseTimesMs.length
    ? Math.round(stats.responseTimesMs.reduce((a, b) => a + b, 0) / stats.responseTimesMs.length) : 0;

  let verdict, severity;
  if (stats.firstBlock && stats.firstBlock <= 10) {
    verdict  = `RESILIENTE — rate limiting activo desde el envío #${stats.blocked}.`;
    severity = 'ok';
  } else if (ratio > 0.6) {
    verdict  = `PARCIAL — ${Math.round(ratio * 100)}% de envíos bloqueados. Umbral mejorable.`;
    severity = 'medium';
  } else if (ratio > 0) {
    verdict  = `TARDÍO — bloqueo tardío o inconsistente (${Math.round(ratio * 100)}% bloqueados).`;
    severity = 'high';
  } else {
    verdict  = `VULNERABLE — ${stats.sent} envíos sin ningún bloqueo. Sin rate limiting en el formulario.`;
    severity = 'critical';
  }

  return {
    profile: 'form-flood', target, mode, severity, verdict,
    formAction: discovery.actionUrl,
    csrfProtected: !!discovery.csrfField,
    stats: { ...stats, blockedRatio: Math.round(ratio * 100), avgResponseMs: avg },
    recommendations: buildFloodRecs(severity, discovery),
  };
}

function detectBodyDifferences(results) {
  const LEAK_PATTERNS = [
    /no.*exist|not.*found|doesn.t.*exist|no.*registrado|no.*encontrado/i,
    /email.*already|ya.*registrado|already.*exist/i,
    /incorrect.*password|contraseña.*incorrecta/i,
    /user.*not.*found|usuario.*no.*encontrado/i,
  ];
  for (const r of results) {
    if (!r.bodySnippet) continue;
    for (const pat of LEAK_PATTERNS) {
      if (pat.test(r.bodySnippet)) {
        return { leaksExistence: true, hint: r.bodySnippet.slice(0, 80) };
      }
    }
  }
  return { leaksExistence: false };
}

function detectSQLError(body) {
  return /sql|syntax error|mysql|postgresql|sqlite|ora-\d|unclosed quotation|unterminated string/i.test(body);
}

function isCSRFField(name, type, value) {
  if (type !== 'hidden') return false;
  return /csrf|_token|authenticity_token|__requestverification|xsrf/i.test(name)
    || (value && value.length > 20 && /^[a-z0-9+/=_-]+$/i.test(value));
}

function extractAttr(attrs, name) {
  const re = new RegExp(`${name}\\s*=\\s*["']([^"']*)["']`, 'i');
  const m  = re.exec(attrs);
  if (m) return m[1];
  // Also try unquoted
  const re2 = new RegExp(`${name}\\s*=\\s*([^\\s>]+)`, 'i');
  const m2  = re2.exec(attrs);
  return m2 ? m2[1] : null;
}

function buildFloodRecs(severity, discovery) {
  const recs = [];
  if (!discovery.csrfField) {
    recs.push('El formulario no tiene protección CSRF. Añade un token único por sesión.');
  }
  if (severity !== 'ok') {
    recs.push('Implementa rate limiting por IP en este endpoint (máx 5-10 envíos por minuto).');
    recs.push('Añade honeypot field oculto — los bots lo rellenan, los humanos no.');
    recs.push('Considera añadir CAPTCHA (hCaptcha, Cloudflare Turnstile) tras 2-3 envíos fallidos.');
  }
  recs.push('Registra IPs con actividad anómala de formulario y alerta en tu SIEM.');
  return recs;
}

function buildInjectRecs(xssHits, sqliHits, severity) {
  const recs = [];
  if (xssHits.length) {
    recs.push(`XSS detectado en campo "${xssHits[0].field}": escapa el output con tu template engine (htmlspecialchars, escapeHtml).`);
    recs.push('Implementa Content-Security-Policy (CSP) para bloquear scripts no autorizados.');
  }
  if (sqliHits.length) {
    recs.push(`SQLi detectado en campo "${sqliHits[0].field}": usa queries parametrizadas o un ORM. Nunca concatenes inputs en SQL.`);
    recs.push('Revisa todos los campos que van a base de datos — no solo el afectado.');
  }
  if (severity === 'ok') {
    recs.push('Sin vulnerabilidades de inyección detectadas. Mantén las dependencias actualizadas.');
  }
  return recs;
}
