/**
 * Fractia CLI — Audit result renderer
 * Two modes: 'expanded' (full findings inline) | 'compact' (summary + on-demand detail)
 */
import chalk from 'chalk';
import readline from 'readline';
import { divider, colors, t } from './theme.js';

// ── Severity styles ──────────────────────────────────────────────────────────
const SEV = {
  critical: { icon: '✖', badge: chalk.hex('#ff2d55').bold,  bar: chalk.hex('#ff2d55'), label: 'CRITICAL' },
  high:     { icon: '▲', badge: chalk.hex('#ff9f1c').bold,  bar: chalk.hex('#ff9f1c'), label: 'HIGH'     },
  medium:   { icon: '◆', badge: chalk.hex('#00b4d8'),        bar: chalk.hex('#00b4d8'), label: 'MEDIUM'   },
  low:      { icon: '◇', badge: chalk.hex('#5a6880'),        bar: chalk.hex('#5a6880'), label: 'LOW'      },
  ok:       { icon: '✓', badge: chalk.hex('#00f5a0'),        bar: chalk.hex('#00f5a0'), label: 'OK'       },
};

// ── Render a single module result (expanded) ─────────────────────────────────
function renderModuleExpanded(result) {
  const sev  = SEV[result.severity] || SEV.ok;
  const name = chalk.bold.white(result.name || result.id);

  console.log('');
  console.log(`  ${sev.bar('▌')} ${sev.badge(`${sev.icon} ${sev.label}`)}  ${name}`);
  console.log(`  ${sev.bar('▌')} ${divider(48)}`);

  if (!result.findings?.length || result.severity === 'ok') {
    console.log(`  ${sev.bar('▌')}  ${colors.dim('Sin hallazgos — módulo limpio.')}`);
    console.log('');
    return;
  }

  for (const finding of result.findings) {
    console.log('');
    console.log(`  ${sev.bar('▌')}  ${chalk.hex('#c8d6f0').bold(finding.title || '—')}`);

    if (finding.description) {
      const lines = wrap(finding.description, 64);
      for (const line of lines) {
        console.log(`  ${sev.bar('▌')}  ${colors.dim(line)}`);
      }
    }

    if (finding.code_example) {
      console.log(`  ${sev.bar('▌')}`);
      console.log(`  ${sev.bar('▌')}  ${chalk.hex('#3a4560')('┌─ ejemplo ──────────────────────────────────────')}`);
      const codeLines = String(finding.code_example).split('\n').slice(0, 6);
      for (const cl of codeLines) {
        console.log(`  ${sev.bar('▌')}  ${chalk.hex('#3a4560')('│')}  ${chalk.hex('#00f5a0')(cl)}`);
      }
      console.log(`  ${sev.bar('▌')}  ${chalk.hex('#3a4560')('└────────────────────────────────────────────────')}`);
    }

    if (finding.cve) {
      console.log(`  ${sev.bar('▌')}  ${colors.dim('CVE')} ${chalk.hex('#ff9f1c')(finding.cve)}`);
    }
  }

  if (result.recommendations?.length) {
    console.log('');
    console.log(`  ${sev.bar('▌')}  ${chalk.hex('#00b4d8')('▸ Recomendaciones')}`);
    for (const rec of result.recommendations) {
      const text = typeof rec === 'string' ? rec : rec.text || rec.title || JSON.stringify(rec);
      const lines = wrap(text, 62);
      console.log(`  ${sev.bar('▌')}    ${chalk.hex('#c8d6f0')('·')} ${chalk.hex('#c8d6f0')(lines[0])}`);
      for (const l of lines.slice(1)) {
        console.log(`  ${sev.bar('▌')}      ${chalk.hex('#c8d6f0')(l)}`);
      }
    }
  }

  console.log('');
}

// ── Render a single module result (compact one-liner) ────────────────────────
function renderModuleCompact(result) {
  const sev     = SEV[result.severity] || SEV.ok;
  const name    = (result.name || result.id || '').padEnd(10);
  const finding = result.findings?.[0];
  const msg     = finding?.title ? `  ${colors.dim('—')}  ${chalk.hex('#c8d6f0')(truncate(finding.title, 50))}` : '';
  console.log(`    ${sev.badge(`${sev.icon} ${sev.label.padEnd(8)}`)}  ${chalk.hex('#c8d6f0')(name)}${msg}`);
}

// ── Public render functions ──────────────────────────────────────────────────

/**
 * Render all results from a completed audit.
 * mode: 'expanded' | 'compact'
 */
export function renderResults(results, { mode = 'expanded', riskScore = 0 } = {}) {
  // Sort: critical → high → medium → low → ok
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3, ok: 4 };
  const sorted = [...results].sort((a, b) =>
    (ORDER[a.severity] ?? 5) - (ORDER[b.severity] ?? 5)
  );

  if (mode === 'expanded') {
    for (const r of sorted) renderModuleExpanded(r);
  } else {
    console.log('');
    for (const r of sorted) renderModuleCompact(r);
    console.log('');
  }
}

/**
 * In compact mode: interactively ask which module to expand.
 */
export async function promptDetailView(results) {
  const names = results.map(r => r.name || r.id);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(res => rl.question(q, res));

  console.log('');
  const input = await ask(
    colors.accent2('  ▸ ') + colors.text(`Ver detalle [${names.join('/')}/${chalk.hex('#00f5a0')('todos')}/no]: `)
  );
  rl.close();

  const ans = input.trim().toLowerCase();
  if (!ans || ans === 'no' || ans === 'n') return;

  if (ans === 'todos' || ans === 'all') {
    renderResults(results, { mode: 'expanded' });
  } else {
    const match = results.find(r => (r.name || r.id) === ans);
    if (match) renderModuleExpanded(match);
    else console.log(`  ${t.fail(`Módulo '${ans}' no encontrado.`)}`);
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function wrap(str, width) {
  if (!str) return [''];
  const words = str.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > width) {
      if (current) lines.push(current);
      current = word;
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [''];
}

function truncate(str, max) {
  return str?.length > max ? str.slice(0, max - 1) + '…' : (str || '');
}
