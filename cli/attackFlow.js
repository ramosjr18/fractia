/**
 * Fractia CLI — Attack Flow (Pilar C: DAST)
 * Handles: safety warning, confirmation, live output, report save
 */
import readline from 'readline';
import path from 'path';
import chalk from 'chalk';
import { divider, colors, t, link } from './theme.js';
import { runAttack, saveAttackReport, PROFILE_LIST } from '../engines/attack/index.js';

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
  const hooks = profile === 'slowloris' ? slowlorisHooks() : stuffingHooks();

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
    // Clear any dangling progress line
    process.stdout.write('\r\x1b[2K');
  }

  printVerdict(result);

  // Save report
  const reportPath = saveAttackReport({ result, target, projectName: new URL(target).hostname });
  const reportUrl  = `file://${reportPath}`;
  console.log(`  ${chalk.hex('#ff9f1c')('▸')} Reporte guardado  ${link(path.basename(reportPath), reportUrl)}`);
  console.log(`    ${colors.dim(reportPath)}`);
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
