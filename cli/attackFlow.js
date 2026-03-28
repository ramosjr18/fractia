/**
 * Fractia CLI — Attack Flow (Pilar C: DAST)
 * Handles: safety warning, confirmation, live output, report save
 */
import readline from 'readline';
import path from 'path';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import { divider, colors, t, link } from './theme.js';
import { runAttack, saveAttackReport, PROFILE_LIST } from '../engines/attack/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FORM_FLOOD_MODES = ['flood', 'user-enum', 'stuffing', 'spam', 'inject'];

// ── readline helper ───────────────────────────────────────────────────────────
function ask(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

// ── Safety warning banner ─────────────────────────────────────────────────────
function printAttackWarning({ target, profile, opts }) {
  const profileMeta = PROFILE_LIST.find(p => p.id === profile);
  const danger  = chalk.hex('#ff2d55').bold;
  const warn    = chalk.hex('#ff9f1c').bold;
  const dim     = colors.dim;

  console.log('');
  console.log(`  ${danger('╔══════════════════════════════════════════════════╗')}`);
  console.log(`  ${danger('║')}  ${warn('⚠  MODO ATAQUE — PILAR C: RED TEAM / DAST')}     ${danger('║')}`);
  console.log(`  ${danger('╚══════════════════════════════════════════════════╝')}`);
  console.log('');
  console.log(`  ${dim('Perfil  ')} ${chalk.bold.white(profileMeta?.name || profile)}`);
  console.log(`  ${dim('Target  ')} ${chalk.hex('#00b4d8')(target)}`);
  if (opts.loginPath)  console.log(`  ${dim('Endpoint')} ${chalk.hex('#c8d6f0')(opts.loginPath)}`);
  if (opts.requests)   console.log(`  ${dim('Requests')} ${chalk.hex('#c8d6f0')(opts.requests)}`);
  if (opts.duration)   console.log(`  ${dim('Duración')} ${chalk.hex('#c8d6f0')(opts.duration + 's')}`);
  console.log('');
  console.log(`  ${warn('ADVERTENCIA')} Este comando envía tráfico real al servidor.`);
  console.log(`  ${dim('Solo usar en entornos que te pertenecen o donde tengas')}`);
  console.log(`  ${dim('autorización explícita por escrito. Uso no autorizado')}`);
  console.log(`  ${dim('puede ser ilegal y constituir un delito informático.')}`);
  console.log('');
}

// ── Confirmation ──────────────────────────────────────────────────────────────
async function confirmAttack(target) {
  console.log(`  ${colors.dim('Para confirmar, escribe la URL del target exactamente:')}`);
  const input = await ask(colors.warn(`  ▸ Confirma [${target}]: `));
  return input === target;
}

// ── Live output: slowloris ────────────────────────────────────────────────────
function slowlorisHooks() {
  return {
    onStart({ connections, duration, target }) {
      console.log('');
      console.log(`  ${chalk.hex('#ff9f1c')('▸')} Abriendo ${chalk.bold(connections)} conexiones hacia ${chalk.hex('#00b4d8')(target)}`);
      console.log(`  ${colors.dim(`Duración: ${duration}s — Ctrl+C para cancelar`)}`);
      console.log('');
    },
    onProgress({ phase, alive, total, dropped, refused }) {
      if (phase === 'opening') {
        process.stdout.write(
          `\r\x1b[2K  ${colors.dim('abriendo')}  ` +
          `${chalk.hex('#00f5a0').bold(alive)} vivas  ` +
          `${chalk.hex('#5a6880')(dropped)} dropeadas  ` +
          `${chalk.hex('#ff2d55')(refused)} rechazadas  ` +
          `${colors.dim(`/ ${total}`)}`
        );
      }
    },
    onAllOpen({ alive, dropped, refused }) {
      process.stdout.write('\r\x1b[2K');
      console.log(
        `  ${chalk.hex('#00f5a0')('✓')} Conexiones abiertas  ` +
        `${chalk.bold.hex('#00f5a0')(alive)} vivas  ` +
        `${colors.dim(dropped + ' dropeadas')}  ` +
        `${colors.dim(refused + ' rechazadas')}`
      );
      console.log('');
      console.log(`  ${colors.dim('tiempo')}  ${colors.dim('vivas')}   ${colors.dim('dropeadas')}  ${colors.dim('servidor')}`);
      console.log(`  ${divider(48)}`);
    },
    onTick({ elapsed, alive, dropped, keptAlive }) {
      console.log(
        `  ${colors.dim(String(elapsed + 's').padEnd(7))}  ` +
        `${chalk.hex('#00f5a0').bold(String(alive).padEnd(6))}  ` +
        `${chalk.hex('#5a6880')(String(dropped).padEnd(10))}  ` +
        `${colors.dim(`${keptAlive} keepalives`)}`
      );
    },
    onProbe({ ts, ms, ok }) {
      const status = ok
        ? chalk.hex('#00f5a0')('✓ responde')
        : chalk.hex('#ff2d55')('✖ sin respuesta');
      console.log(
        `  ${colors.dim(String(ts + 's').padEnd(7))}  ` +
        `${colors.dim('probe')}   ` +
        `${colors.dim('          ')}  ` +
        `${status} ${colors.dim(ms + 'ms')}`
      );
    },
  };
}

// ── Live output: bots-stuffing ────────────────────────────────────────────────
function stuffingHooks() {
  let lastLine = '';
  return {
    onStart({ loginUrl, requests, concurrency, duration }) {
      console.log('');
      console.log(`  ${chalk.hex('#ff9f1c')('▸')} Credential stuffing → ${chalk.hex('#00b4d8')(loginUrl)}`);
      console.log(`  ${colors.dim(`${requests} requests · concurrency ${concurrency} · max ${duration}s`)}`);
      console.log('');
      console.log(`  ${colors.dim('enviados  bloqueados  ok  errores  último status')}`);
      console.log(`  ${divider(52)}`);
    },
    onBatch({ done, total, stats }) {
      const pct     = Math.round((done / total) * 100);
      const bar     = barStr(pct, 20);
      const blocked = stats.blocked > 0
        ? chalk.hex('#ff9f1c').bold(String(stats.blocked).padEnd(10))
        : colors.dim(String(stats.blocked).padEnd(10));
      process.stdout.write(
        `\r\x1b[2K  ` +
        `${chalk.hex('#c8d6f0')(String(done).padEnd(9))} ` +
        `${blocked}` +
        `${chalk.hex('#00f5a0')(String(stats.ok).padEnd(4))} ` +
        `${chalk.hex('#ff2d55')(String(stats.errors).padEnd(9))} ` +
        `${colors.dim(bar + ' ' + pct + '%')}`
      );
    },
  };
}

// ── Live output: recon ────────────────────────────────────────────────────────
function reconHooks() {
  const PHASE_LABELS = {
    recon:   'Iniciando reconocimiento',
    headers: 'Headers de seguridad',
    paths:   'Rutas sensibles',
    cors:    'CORS',
  };
  const SEV_COLOR = {
    critical: chalk.hex('#ff2d55').bold,
    high:     chalk.hex('#ff9f1c').bold,
    medium:   chalk.hex('#00b4d8'),
    low:      chalk.hex('#5a6880'),
    info:     colors.dim,
  };

  return {
    onPhase(phase) {
      process.stdout.write(`\r\x1b[2K  ${chalk.hex('#a78bfa')('◈')}  ${colors.dim(PHASE_LABELS[phase] || phase)}`);
    },
    onHeaderCheck({ label, present, value, severity }) {
      process.stdout.write('\r\x1b[2K');
      if (present) {
        const truncated = value ? value.slice(0, 55) : '';
        console.log(`  ${chalk.hex('#00f5a0')('✓')}  ${chalk.hex('#c8d6f0')(label.padEnd(24))}  ${colors.dim(truncated)}`);
      } else {
        const sevFn = SEV_COLOR[severity] || colors.dim;
        console.log(`  ${sevFn('✖')}  ${chalk.hex('#c8d6f0')(label.padEnd(24))}  ${sevFn('AUSENTE')}`);
      }
    },
    onTechDetected(tech) {
      if (tech.length) {
        console.log('');
        console.log(`  ${chalk.hex('#a78bfa')('◈')}  ${colors.dim('Stack detectado')}  ${tech.map(t => chalk.hex('#00b4d8')(t)).join('  ')}`);
      }
    },
    onPathProbe({ path, label, status, found, severity }) {
      process.stdout.write('\r\x1b[2K');
      if (found && severity !== 'info') {
        const sevFn = SEV_COLOR[severity] || colors.dim;
        console.log(`  ${sevFn('✖')}  ${sevFn(label.padEnd(24))}  ${colors.dim(`HTTP ${status}`)}  ${chalk.hex('#5a6880')(path)}`);
      } else if (found && severity === 'info') {
        console.log(`  ${colors.dim('·')}  ${colors.dim(label.padEnd(24))}  ${colors.dim(`HTTP ${status}`)}`);
      }
    },
    onCorsCheck({ origin, acao, vulnerable }) {
      process.stdout.write('\r\x1b[2K');
      if (vulnerable) {
        console.log(`  ${chalk.hex('#ff2d55').bold('✖')}  ${chalk.hex('#ff2d55').bold('CORS')}: Origin "${origin}" → ${chalk.hex('#ff2d55')(acao)}`);
      }
    },
  };
}

// ── Live output: spike-test ───────────────────────────────────────────────────
function spikeTestHooks() {
  return {
    onStart({ target, requests, concurrency, method }) {
      console.log('');
      console.log(`  ${chalk.hex('#ff9f1c')('▸')} Spike Test  ${chalk.hex('#00b4d8')(method)}  ${chalk.hex('#00b4d8')(target)}`);
      console.log(`  ${colors.dim(`${requests} requests · ${concurrency} concurrentes`)}`);
      console.log('');
      console.log(`  ${colors.dim('enviados   ok   bloqueados   5xx   timeouts   p95ms   rps')}`);
      console.log(`  ${divider(58)}`);
    },
    onBatch({ done, total, elapsed, stats }) {
      const pct  = Math.round((done / total) * 100);
      const bar  = barStr(pct, 14);
      const times = stats.responseTimes || [];
      const sorted = [...times].sort((a, b) => a - b);
      const p95  = sorted[Math.floor(sorted.length * 0.95)] || 0;
      const rps  = elapsed > 0 ? Math.round(done / elapsed) : 0;
      const rl   = stats.rateLimited > 0
        ? chalk.hex('#00f5a0').bold(String(stats.rateLimited).padEnd(12))
        : colors.dim(String(stats.rateLimited).padEnd(12));
      const err5xx = stats.serverErrors > 0
        ? chalk.hex('#ff2d55').bold(String(stats.serverErrors).padEnd(5))
        : colors.dim(String(stats.serverErrors).padEnd(5));
      process.stdout.write(
        `\r\x1b[2K  ` +
        `${chalk.hex('#c8d6f0')(String(done).padEnd(10))}` +
        `${chalk.hex('#00f5a0')(String(stats.ok).padEnd(5))}` +
        `${rl}` +
        `${err5xx}` +
        `${colors.dim(String(stats.timeouts).padEnd(11))}` +
        `${chalk.hex('#00b4d8')(String(p95 + 'ms').padEnd(8))}` +
        `${colors.dim(String(rps) + '/s')}  ` +
        `${colors.dim(bar)}`
      );
    },
  };
}

// ── Recon verdict renderer ────────────────────────────────────────────────────
function printReconVerdict(result) {
  const SEV = {
    critical: { icon: '✖', color: chalk.hex('#ff2d55').bold },
    high:     { icon: '▲', color: chalk.hex('#ff9f1c').bold },
    medium:   { icon: '◆', color: chalk.hex('#00b4d8')      },
    low:      { icon: '◇', color: chalk.hex('#5a6880')      },
    ok:       { icon: '✓', color: chalk.hex('#00f5a0')      },
  };
  const sev = SEV[result.severity] || SEV.medium;

  console.log('');
  console.log(`  ${divider(58)}`);
  console.log('');
  console.log(`  ${sev.color(`${sev.icon} ${result.severity.toUpperCase()}`)}  ${chalk.bold.white(result.verdict)}`);
  console.log('');

  const s = result.stats;
  console.log(`  ${colors.dim('Headers revisados')}   ${chalk.hex('#c8d6f0')(s.headersChecked)}`);
  console.log(`  ${colors.dim('Headers ausentes')}    ${s.headersMissing > 0 ? chalk.hex('#ff9f1c').bold(s.headersMissing) : chalk.hex('#00f5a0')('0')}`);
  console.log(`  ${colors.dim('Rutas encontradas')}   ${s.pathsFound > 0 ? chalk.hex('#ff2d55').bold(s.pathsFound) : chalk.hex('#00f5a0')('0')} ${colors.dim(`/ ${s.pathsProbed} probadas`)}`);
  console.log(`  ${colors.dim('CORS misconfigured')}  ${s.corsVulnerable ? chalk.hex('#ff2d55').bold('Sí') : chalk.hex('#00f5a0')('No')}`);

  if (result.infoLeaks?.length) {
    console.log('');
    console.log(`  ${chalk.hex('#ff9f1c')('▸')} Info leaks en headers`);
    for (const l of result.infoLeaks) {
      console.log(`    ${colors.dim(l.type.padEnd(18))}  ${chalk.hex('#c8d6f0')(l.value)}`);
    }
  }

  if (result.recommendations?.length) {
    console.log('');
    console.log(`  ${chalk.hex('#00b4d8')('▸ Recomendaciones')}`);
    for (const rec of result.recommendations) {
      const lines = wordWrap(rec, 60);
      console.log(`    ${colors.dim('·')} ${chalk.hex('#c8d6f0')(lines[0])}`);
      for (const l of lines.slice(1)) console.log(`      ${chalk.hex('#c8d6f0')(l)}`);
    }
  }
  console.log('');
}

// ── Spike-test verdict renderer ───────────────────────────────────────────────
function printSpikeVerdict(result) {
  const SEV = {
    critical: { icon: '✖', color: chalk.hex('#ff2d55').bold },
    high:     { icon: '▲', color: chalk.hex('#ff9f1c').bold },
    medium:   { icon: '◆', color: chalk.hex('#00b4d8')      },
    low:      { icon: '◇', color: chalk.hex('#5a6880')      },
    ok:       { icon: '✓', color: chalk.hex('#00f5a0')      },
  };
  const sev = SEV[result.severity] || SEV.medium;

  console.log('');
  console.log(`  ${divider(58)}`);
  console.log('');
  console.log(`  ${sev.color(`${sev.icon} ${result.severity.toUpperCase()}`)}  ${chalk.bold.white(result.verdict)}`);
  console.log('');

  const s = result.stats;
  console.log(`  ${colors.dim('Requests enviados')}   ${chalk.hex('#c8d6f0')(s.sent)}`);
  console.log(`  ${colors.dim('OK (2xx/3xx)')}        ${chalk.hex('#00f5a0')(s.ok)}`);
  console.log(`  ${colors.dim('Bloqueados (429)')}    ${s.rateLimited > 0 ? chalk.hex('#00f5a0').bold(s.rateLimited) : chalk.hex('#ff2d55')('0')}  ${colors.dim(`(${s.rateLimitedRatio}%)`)}`);
  if (s.firstRateLimit) console.log(`  ${colors.dim('Primer bloqueo en')}   ${chalk.hex('#00f5a0')('#' + s.firstRateLimit)}`);
  console.log(`  ${colors.dim('Errores 5xx')}         ${s.serverErrors > 0 ? chalk.hex('#ff2d55').bold(s.serverErrors) : chalk.hex('#00f5a0')('0')}`);
  console.log(`  ${colors.dim('Timeouts')}            ${chalk.hex('#5a6880')(s.timeouts)}`);
  console.log('');
  console.log(`  ${colors.dim('Avg')}   ${chalk.hex('#00b4d8')(s.avgMs + 'ms')}   ${colors.dim('P50')}  ${chalk.hex('#00b4d8')(s.p50Ms + 'ms')}   ${colors.dim('P95')}  ${chalk.hex('#00b4d8')(s.p95Ms + 'ms')}   ${colors.dim('P99')}  ${chalk.hex('#00b4d8')(s.p99Ms + 'ms')}`);
  console.log(`  ${colors.dim('Throughput')}          ${chalk.hex('#00b4d8')(s.rps + ' req/s')}  ${colors.dim(`(${(s.totalMs / 1000).toFixed(1)}s total)`)}`);

  const statuses = Object.entries(s.statuses || {}).sort((a, b) => b[1] - a[1]);
  if (statuses.length) {
    console.log('');
    console.log(`  ${colors.dim('Distribución')}  ${statuses.map(([k, v]) => `${colors.dim(k + ':')}${chalk.hex('#c8d6f0')(v)}`).join('  ')}`);
  }

  if (result.recommendations?.length) {
    console.log('');
    console.log(`  ${chalk.hex('#00b4d8')('▸ Recomendaciones')}`);
    for (const rec of result.recommendations) {
      const lines = wordWrap(rec, 60);
      console.log(`    ${colors.dim('·')} ${chalk.hex('#c8d6f0')(lines[0])}`);
      for (const l of lines.slice(1)) console.log(`      ${chalk.hex('#c8d6f0')(l)}`);
    }
  }
  console.log('');
}

// ── Live output: form-flood ───────────────────────────────────────────────────
function formFloodHooks(mode) {
  return {
    onPhase(phase, msg) {
      process.stdout.write(`\r\x1b[2K  ${colors.dim(phase)}  ${chalk.hex('#00b4d8')(msg)}`);
    },
    onFormFound({ formsFound, form, actionUrl, csrfField, manual }) {
      process.stdout.write('\r\x1b[2K');
      const label = manual ? 'Formulario manual (SPA)' : 'Formulario encontrado';
      console.log(`  ${chalk.hex('#00f5a0')('✓')} ${label}  ${colors.dim(`action: ${actionUrl}`)}`);
      if (csrfField) console.log(`  ${colors.dim('  csrf token:')} ${chalk.hex('#a78bfa')(csrfField)}`);
      const fieldNames = form.filter(f => !Array.isArray(f) && f.name).map(f => f.name).join(', ');
      console.log(`  ${colors.dim('  campos:')} ${chalk.hex('#c8d6f0')(fieldNames)}`);
      console.log('');
    },
    onStart({ mode, requests, target }) {
      const modeColors = { flood: '#ff9f1c', 'user-enum': '#00b4d8', stuffing: '#ff2d55', spam: '#a78bfa', inject: '#ff9f1c' };
      const c = chalk.hex(modeColors[mode] || '#ff9f1c');
      console.log(`  ${c('▸')} Modo ${c.bold(mode.toUpperCase())} → ${chalk.hex('#00b4d8')(target)}`);
      if (requests) console.log(`  ${colors.dim(`${requests} envíos`)}`);
      console.log('');
      if (mode === 'inject') {
        console.log(`  ${colors.dim('tipo   campo       payload                              status   reflect')}`);
        console.log(`  ${divider(68)}`);
      } else if (mode === 'user-enum') {
        console.log(`  ${colors.dim('email                                    status   ms      señal')}`);
        console.log(`  ${divider(68)}`);
      } else {
        console.log(`  ${colors.dim('enviados  bloqueados  ok  errores  progreso')}`);
        console.log(`  ${divider(52)}`);
      }
    },
    onBatch({ done, total, stats }) {
      const pct  = Math.round((done / total) * 100);
      const bar  = barStr(pct, 16);
      const blk  = stats.blocked > 0
        ? chalk.hex('#ff9f1c').bold(String(stats.blocked).padEnd(10))
        : colors.dim(String(stats.blocked).padEnd(10));
      process.stdout.write(
        `\r\x1b[2K  ${chalk.hex('#c8d6f0')(String(done).padEnd(9))}` +
        `${blk}${chalk.hex('#00f5a0')(String(stats.ok).padEnd(4))} ` +
        `${chalk.hex('#ff2d55')(String(stats.errors).padEnd(9))}${colors.dim(bar + ' ' + pct + '%')}`
      );
    },
    onEnumResult({ email, status, ms, body }) {
      const statusC = status === 200 ? chalk.hex('#00f5a0') : status === 429 ? chalk.hex('#ff9f1c') : colors.dim;
      const snippet = (body || '').replace(/\s+/g, ' ').trim().slice(0, 35);
      console.log(
        `  ${chalk.hex('#c8d6f0')(email.padEnd(40))} ` +
        `${statusC(String(status).padEnd(8))} ${colors.dim(String(ms) + 'ms').padEnd(8)}  ` +
        `${colors.dim(snippet)}`
      );
    },
    onInjectResult({ type, field, payload, status, reflected, sqlError, timingHit, bodySnippet }) {
      const hit = reflected || sqlError || timingHit;
      const icon = hit ? chalk.hex('#ff2d55').bold('✖ HIT') : chalk.hex('#00f5a0')('✓ ok ');
      const typeC = type === 'XSS' ? chalk.hex('#ff9f1c') : chalk.hex('#ff2d55');
      console.log(
        `  ${icon}  ${typeC(type.padEnd(5))} ${chalk.hex('#c8d6f0')(field.padEnd(11))} ` +
        `${colors.dim(payload.slice(0, 36).padEnd(38))} ${colors.dim(String(status))}` +
        (hit ? `  ${chalk.hex('#ff2d55').bold('← VULNERABLE')}` : '')
      );
    },
  };
}

// ── Verdict renderer ──────────────────────────────────────────────────────────
function printVerdict(result) {
  const SEV = {
    critical: { icon: '✖', color: chalk.hex('#ff2d55').bold },
    high:     { icon: '▲', color: chalk.hex('#ff9f1c').bold },
    medium:   { icon: '◆', color: chalk.hex('#00b4d8')      },
    low:      { icon: '◇', color: chalk.hex('#5a6880')      },
    ok:       { icon: '✓', color: chalk.hex('#00f5a0')      },
  };
  const sev = SEV[result.severity] || SEV.medium;

  console.log('');
  console.log(`  ${divider(52)}`);
  console.log('');
  console.log(`  ${sev.color(`${sev.icon} ${result.severity.toUpperCase()}`)}  ${chalk.bold.white(result.verdict)}`);
  console.log('');

  // Stats summary
  const s = result.stats;
  if (result.profile === 'slowloris') {
    console.log(`  ${colors.dim('Conexiones intentadas')}  ${chalk.hex('#c8d6f0')(s.connectionsAttempted)}`);
    console.log(`  ${colors.dim('Vivas al final')}         ${chalk.hex('#00f5a0')(s.alive)}`);
    console.log(`  ${colors.dim('Dropeadas')}              ${chalk.hex('#5a6880')(s.dropped)}  ${colors.dim(`(${s.droppedRatio}%)`)}`);
    console.log(`  ${colors.dim('Rechazadas')}             ${chalk.hex('#ff2d55')(s.refused)}`);
    console.log(`  ${colors.dim('Servidor sin respuesta')} ${s.serverUnresponsive ? chalk.hex('#ff2d55')('Sí') : chalk.hex('#00f5a0')('No')}`);
    console.log(`  ${colors.dim('Servidor recuperado')}    ${s.serverRecovered ? chalk.hex('#00f5a0')('Sí') : chalk.hex('#ff2d55')('No')}`);
  } else if (result.profile === 'form-flood') {
    const s = result.stats;
    console.log(`  ${colors.dim('Modo')}                   ${chalk.hex('#ff9f1c')(result.mode)}`);
    console.log(`  ${colors.dim('Form action')}            ${chalk.hex('#00b4d8')(result.formAction || '—')}`);
    console.log(`  ${colors.dim('CSRF protegido')}         ${result.csrfProtected ? chalk.hex('#00f5a0')('Sí') : chalk.hex('#ff2d55')('No')}`);
    if (result.mode === 'inject') {
      console.log(`  ${colors.dim('Payloads probados')}      ${chalk.hex('#c8d6f0')(s.payloadsTested)}`);
      console.log(`  ${colors.dim('Campos probados')}        ${chalk.hex('#c8d6f0')(s.fieldsProbed)}`);
      console.log(`  ${colors.dim('Vulnerabilidades')}       ${s.vulnerabilities > 0 ? chalk.hex('#ff2d55').bold(s.vulnerabilities) : chalk.hex('#00f5a0')('0')}`);
      if (result.findings?.length) {
        console.log('');
        for (const f of result.findings) {
          const tag = f.type === 'XSS' ? chalk.hex('#ff9f1c').bold('XSS') : chalk.hex('#ff2d55').bold('SQLi');
          console.log(`  ${tag}  campo ${chalk.hex('#c8d6f0')(f.field)}  ${colors.dim(`"${f.payload.slice(0, 40)}"`)}`);
        }
      }
    } else if (result.mode === 'user-enum') {
      console.log(`  ${colors.dim('Emails testeados')}       ${chalk.hex('#c8d6f0')(s.tested)}`);
      console.log(`  ${colors.dim('Leak detectado')}         ${s.bodyLeaks ? chalk.hex('#ff2d55').bold('Sí') : chalk.hex('#00f5a0')('No')}`);
    } else {
      console.log(`  ${colors.dim('Envíos realizados')}      ${chalk.hex('#c8d6f0')(s.sent)}`);
      console.log(`  ${colors.dim('Bloqueados')}             ${chalk.hex('#ff9f1c')(s.blocked)}  ${colors.dim(`(${s.blockedRatio}%)`)}`);
      const statuses = Object.entries(s.statuses || {}).sort((a, b) => b[1] - a[1]);
      if (statuses.length) console.log(`  ${colors.dim('Distribución status')}    ${statuses.map(([k,v]) => `${colors.dim(k+':')}${chalk.hex('#c8d6f0')(v)}`).join('  ')}`);
    }
  } else if (result.profile === 'bots-stuffing') {
    console.log(`  ${colors.dim('Requests enviados')}      ${chalk.hex('#c8d6f0')(s.sent)}`);
    console.log(`  ${colors.dim('Bloqueados (429)')}       ${chalk.hex('#ff9f1c')(s.blocked)}  ${colors.dim(`(${s.blockedRatio}%)`)}`);
    if (s.firstBlock)   console.log(`  ${colors.dim('Primer bloqueo en')}      ${chalk.hex('#ff9f1c')('#' + s.firstBlock)}`);
    if (s.firstLockout) console.log(`  ${colors.dim('Lockout de cuenta en')}   ${chalk.hex('#ff9f1c')('#' + s.firstLockout)}`);
    console.log(`  ${colors.dim('IP baneada')}             ${s.ipBanned ? chalk.hex('#00f5a0')('Sí') : chalk.hex('#ff2d55')('No')}`);
    console.log(`  ${colors.dim('CAPTCHA detectado')}      ${s.captchaDetected ? chalk.hex('#00f5a0')('Sí') : chalk.hex('#ff2d55')('No')}`);
    console.log(`  ${colors.dim('Avg response time')}      ${chalk.hex('#00b4d8')(s.avgResponseMs + 'ms')}`);
    // Status distribution
    const statuses = Object.entries(s.statuses).sort((a, b) => b[1] - a[1]);
    if (statuses.length) {
      console.log(`  ${colors.dim('Distribución status')}    ${statuses.map(([k,v]) => `${colors.dim(k+':')}${chalk.hex('#c8d6f0')(v)}`).join('  ')}`);
    }
  }

  if (result.recommendations?.length) {
    console.log('');
    console.log(`  ${chalk.hex('#00b4d8')('▸ Recomendaciones')}`);
    for (const rec of result.recommendations) {
      const lines = wordWrap(rec, 60);
      console.log(`    ${colors.dim('·')} ${chalk.hex('#c8d6f0')(lines[0])}`);
      for (const l of lines.slice(1)) console.log(`      ${chalk.hex('#c8d6f0')(l)}`);
    }
  }
  console.log('');
}

// ── Main entry points ─────────────────────────────────────────────────────────

/**
 * Direct CLI mode: fractia attack --target URL --profile PROFILE [--login-path PATH ...]
 */
export async function runAttackCLI({ target, profile, opts }) {
  printAttackWarning({ target, profile, opts });

  const confirmed = await confirmAttack(target);
  if (!confirmed) {
    console.log('');
    console.log(`  ${t.fail('Cancelado.')}`);
    console.log('');
    process.exit(0);
  }

  console.log('');
  await executeAttack({ target, profile, opts });
}

/**
 * Interactive menu mode (called from fractia.js menu[3])
 */
export async function runAttackInteractive() {
  // Profile selection
  console.log('');
  console.log(`  ${chalk.hex('#ff9f1c').bold('Attack / DAST')}  ${colors.dim('— Pilar C: Red Team')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  PROFILE_LIST.forEach((p, i) => {
    const riskColor = p.risk === 'high'
      ? chalk.hex('#ff2d55')
      : chalk.hex('#ff9f1c');
    console.log(
      `  ${chalk.hex('#00b4d8').bold(`[${i + 1}]`)}  ${chalk.bold.white(p.name)}  ` +
      `${riskColor(`[${p.risk}]`)}`
    );
    console.log(`       ${colors.dim(p.description)}`);
  });
  console.log('');

  const pAns    = await ask(colors.accent2('  ▸ ') + colors.text('Perfil [1-' + PROFILE_LIST.length + ']: '));
  const pIdx    = parseInt(pAns, 10) - 1;
  const profile = PROFILE_LIST[pIdx];
  if (!profile) { console.log(`  ${t.fail('Perfil no válido.')}`); return; }

  // Target
  const target = await ask(colors.accent2('  ▸ ') + colors.text('Target URL: '));
  if (!target.startsWith('http')) {
    console.log(`  ${t.fail('URL inválida. Debe empezar con http:// o https://')}`);
    return;
  }

  // Profile-specific options
  const opts = {};
  if (profile.requiredOpts?.includes('loginPath')) {
    opts.loginPath = await ask(colors.accent2('  ▸ ') + colors.text('Login path (ej: /api/auth/login): '));
    const bodyTmpl = await ask(colors.accent2('  ▸ ') + colors.text('Body template [Enter para default email+password]: '));
    if (bodyTmpl) opts.bodyTemplate = bodyTmpl;
  }

  // form-flood specific options
  if (profile.id === 'form-flood') {
    console.log('');
    console.log(`  ${colors.dim('modos disponibles')}`);
    const MODES = [
      { id: 'flood',     desc: 'Envío masivo — valida rate limiting en el formulario' },
      { id: 'user-enum', desc: 'Detecta si el servidor revela si un email existe' },
      { id: 'stuffing',  desc: 'Credential stuffing con CSRF + cookies de sesión' },
      { id: 'spam',      desc: 'Flood de contenido (contacto, comentarios, newsletter)' },
      { id: 'inject',    desc: 'Payloads XSS + SQLi en cada campo del formulario' },
      { id: 'all',       desc: chalk.hex('#a78bfa')('Corre todos los modos en secuencia') + colors.dim(' · reporte consolidado') },
    ];
    MODES.forEach((m, i) => {
      console.log(t.option(`[${i + 1}]`, `${m.id.padEnd(10)} ${colors.dim(m.desc)}`));
    });
    console.log('');
    const mAns = await ask(colors.accent2('  ▸ ') + colors.text('Modo [1-6]: '));
    opts.mode = MODES[(parseInt(mAns, 10) - 1)]?.id || 'flood';

    const fiAns = await ask(colors.accent2('  ▸ ') + colors.text('Índice del formulario si hay varios [0]: '));
    if (fiAns) opts.formIndex = parseInt(fiAns, 10);
  }

  // Optional overrides
  const reqAns = await ask(colors.accent2('  ▸ ') + colors.text('Requests [200]: '));
  if (reqAns) opts.requests = parseInt(reqAns, 10);

  const durAns = await ask(colors.accent2('  ▸ ') + colors.text('Duración máx en segundos [30]: '));
  if (durAns) opts.duration = parseInt(durAns, 10);

  printAttackWarning({ target, profile: profile.id, opts });

  const confirmed = await confirmAttack(target);
  if (!confirmed) {
    console.log(`  ${t.fail('Cancelado.')}`);
    return;
  }

  console.log('');
  await executeAttack({ target, profile: profile.id, opts });
}

// ── Shared execution ──────────────────────────────────────────────────────────
async function executeAttack({ target, profile, opts }) {
  // ── ALL mode: run every form-flood mode in sequence ──────────────────────────
  if (profile === 'form-flood' && opts.mode === 'all') {
    await executeFormFloodAll({ target, opts });
    return;
  }

  const hooks = profile === 'recon'
    ? reconHooks()
    : profile === 'spike-test'
      ? spikeTestHooks()
      : profile === 'slowloris'
        ? slowlorisHooks()
        : profile === 'form-flood'
          ? formFloodHooks(opts.mode || 'flood')
          : stuffingHooks();

  // Graceful Ctrl+C
  let result;
  const onSigint = () => {
    console.log('');
    console.log(`  ${chalk.hex('#ff9f1c')('⚠')} Ataque interrumpido manualmente.`);
    process.exit(0);
  };
  process.once('SIGINT', onSigint);

  try {
    result = await runAttack({ profile, target, opts, hooks });
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.stdout.write('\r\x1b[2K');
  }

  if (result.profile === 'recon')       printReconVerdict(result);
  else if (result.profile === 'spike-test') printSpikeVerdict(result);
  else                                  printVerdict(result);

  const reportPath = saveAttackReport({ result, target, projectName: new URL(target).hostname });
  const reportUrl  = `file://${reportPath}`;
  console.log(`  ${chalk.hex('#ff9f1c')('▸')} Reporte guardado  ${link(path.basename(reportPath), reportUrl)}`);
  console.log(`    ${colors.dim(reportPath)}`);
  console.log('');
}

// ── Form-flood ALL: run all 5 modes sequentially ──────────────────────────────
async function executeFormFloodAll({ target, opts }) {
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const allResults = [];

  console.log('');
  console.log(
    `  ${chalk.hex('#a78bfa').bold('◈ MODO ALL')}  ` +
    `${colors.dim('Corriendo todos los modos de form-flood en secuencia')}`
  );
  console.log(`  ${divider(58)}`);

  for (let i = 0; i < FORM_FLOOD_MODES.length; i++) {
    const mode = FORM_FLOOD_MODES[i];
    const num  = `[${i + 1}/${FORM_FLOOD_MODES.length}]`;

    console.log('');
    console.log(`  ${chalk.hex('#00b4d8')(num)}  Iniciando modo ${chalk.bold.white(mode)}`);
    console.log('');

    let result;
    const hooks = formFloodHooks(mode);

    const onSigint = () => {
      console.log('');
      console.log(`  ${chalk.hex('#ff9f1c')('⚠')} Ataque interrumpido.`);
      process.exit(0);
    };
    process.once('SIGINT', onSigint);

    try {
      result = await runAttack({ profile: 'form-flood', target, opts: { ...opts, mode }, hooks });
    } finally {
      process.removeListener('SIGINT', onSigint);
      process.stdout.write('\r\x1b[2K');
    }

    allResults.push(result);

    // Print compact verdict for this mode
    const SEV = {
      critical: chalk.hex('#ff2d55').bold,
      high:     chalk.hex('#ff9f1c').bold,
      medium:   chalk.hex('#00b4d8'),
      low:      chalk.hex('#5a6880'),
      ok:       chalk.hex('#00f5a0'),
    };
    const sevFn = SEV[result.severity] || SEV.medium;
    console.log('');
    console.log(`  ${sevFn(`${result.severity.toUpperCase()}`.padEnd(10))}  ${colors.dim(result.verdict)}`);
    // Only print injection-style findings (have payload + field)
    const injFindings = (result.findings || []).filter(f => f.payload && f.field);
    if (injFindings.length) {
      for (const f of injFindings.slice(0, 3)) {
        const tag = f.type === 'XSS' ? chalk.hex('#ff9f1c').bold('XSS') : chalk.hex('#ff2d55').bold('SQLi');
        console.log(`    ${tag}  ${chalk.hex('#c8d6f0')(f.field)}  ${colors.dim(`"${f.payload.slice(0, 45)}"`)}`);
      }
    }
  }

  // ── Consolidated summary ───────────────────────────────────────────────────
  const worstSev = allResults.reduce((best, r) =>
    (SEV_RANK[r.severity] ?? 0) > (SEV_RANK[best] ?? 0) ? r.severity : best, 'ok');

  const SEV_ICONS = {
    critical: chalk.hex('#ff2d55').bold('✖ CRITICAL'),
    high:     chalk.hex('#ff9f1c').bold('▲ HIGH'),
    medium:   chalk.hex('#00b4d8')('◆ MEDIUM'),
    low:      chalk.hex('#5a6880')('◇ LOW'),
    ok:       chalk.hex('#00f5a0')('✓ OK'),
  };

  console.log('');
  console.log(`  ${divider(58)}`);
  console.log('');
  console.log(`  ${chalk.hex('#a78bfa').bold('◈ RESUMEN CONSOLIDADO')}`);
  console.log('');
  console.log(`  ${colors.dim('Severidad global')}   ${SEV_ICONS[worstSev] || worstSev}`);
  console.log('');
  console.log(`  ${colors.dim('modo'.padEnd(12))}  ${colors.dim('severidad'.padEnd(10))}  ${colors.dim('veredicto')}`);
  console.log(`  ${divider(58)}`);

  for (const r of allResults) {
    const sevFn = {
      critical: chalk.hex('#ff2d55').bold,
      high:     chalk.hex('#ff9f1c').bold,
      medium:   chalk.hex('#00b4d8'),
      low:      chalk.hex('#5a6880'),
      ok:       chalk.hex('#00f5a0'),
    }[r.severity] || (x => x);
    console.log(
      `  ${chalk.hex('#c8d6f0')((r.mode || '—').padEnd(12))}  ` +
      `${sevFn((r.severity || '—').padEnd(10))}  ` +
      `${colors.dim(r.verdict || '')}`
    );
  }

  // Total injection findings
  // Only count injection findings (have payload + field + type)
  const allInjFindings = allResults.flatMap(r => (r.findings || []).filter(f => f.payload && f.field));
  if (allInjFindings.length > 0) {
    console.log('');
    console.log(`  ${chalk.hex('#ff2d55').bold(`✖ ${allInjFindings.length} vulnerabilidades encontradas`)}`);
    for (const f of allInjFindings) {
      const tag = f.type === 'XSS' ? chalk.hex('#ff9f1c').bold('XSS') : chalk.hex('#ff2d55').bold('SQLi');
      console.log(`    ${tag}  campo ${chalk.hex('#c8d6f0')(f.field)}  ${colors.dim(`"${f.payload.slice(0, 50)}"`)}`);
    }
  }

  // Unique recommendations across all modes
  const allRecs = [...new Set(allResults.flatMap(r => r.recommendations || []))];
  if (allRecs.length) {
    console.log('');
    console.log(`  ${chalk.hex('#00b4d8')('▸ Recomendaciones')}`);
    for (const rec of allRecs) {
      const lines = wordWrap(rec, 60);
      console.log(`    ${colors.dim('·')} ${chalk.hex('#c8d6f0')(lines[0])}`);
      for (const l of lines.slice(1)) console.log(`      ${chalk.hex('#c8d6f0')(l)}`);
    }
  }

  console.log('');

  // ── Save consolidated report ───────────────────────────────────────────────
  const reportsDir = path.join(__dirname, '..', 'reports');
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });

  const ts        = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const hostname  = new URL(target).hostname.replace(/[^a-z0-9_-]/gi, '_');
  const filename  = `${hostname}_form-flood_ALL_${ts}.json`;
  const filepath  = path.join(reportsDir, filename);

  const report = {
    meta: {
      tool:        'Fractia v3.0.0 — Pilar C DAST',
      profile:     'form-flood',
      mode:        'all',
      target,
      generatedAt: new Date().toISOString(),
      severityGlobal: worstSev,
    },
    summary: {
      modesRun:        FORM_FLOOD_MODES.length,
      worstSeverity:   worstSev,
      totalFindings:   allInjFindings.length,
      recommendations: allRecs,
    },
    modes: allResults.map(r => ({
      mode:            r.mode,
      severity:        r.severity,
      verdict:         r.verdict,
      stats:           r.stats,
      findings:        r.findings || [],
      recommendations: r.recommendations || [],
    })),
  };

  writeFileSync(filepath, JSON.stringify(report, null, 2), 'utf8');
  const reportUrl = `file://${filepath}`;
  console.log(`  ${chalk.hex('#ff9f1c')('▸')} Reporte consolidado  ${link(filename, reportUrl)}`);
  console.log(`    ${colors.dim(filepath)}`);
  console.log('');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function barStr(pct, width) {
  const filled = Math.round((pct / 100) * width);
  return chalk.hex('#00f5a0')('█'.repeat(filled)) + chalk.hex('#1a2035')('░'.repeat(width - filled));
}

function wordWrap(str, width) {
  const words = str.split(' ');
  const lines = [];
  let cur = '';
  for (const w of words) {
    if ((cur + ' ' + w).trim().length > width && cur) { lines.push(cur); cur = w; }
    else cur = (cur + ' ' + w).trim();
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [''];
}
