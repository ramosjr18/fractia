/**
 * Fractia CLI — Live audit feedback
 * Prints real-time progress to the terminal as audits run from the browser UI
 */
import chalk from 'chalk';
import path from 'path';
import { divider, colors } from './theme.js';

// ── Severity config ──────────────────────────────────────────────────────────
const SEVERITY = {
  critical: { icon: '✖', color: chalk.hex('#ff2d55').bold,  label: 'CRITICAL' },
  high:     { icon: '▲', color: chalk.hex('#ff9f1c').bold,  label: 'HIGH    ' },
  medium:   { icon: '◆', color: chalk.hex('#00b4d8'),        label: 'MEDIUM  ' },
  low:      { icon: '◇', color: chalk.hex('#5a6880'),        label: 'LOW     ' },
  ok:       { icon: '✓', color: chalk.hex('#00f5a0'),        label: 'OK      ' },
};

const SPIN_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// ── Single-line spinner tied to a status string ──────────────────────────────
class LineSpinner {
  constructor() {
    this.frame    = 0;
    this.text     = '';
    this.interval = null;
    this.active   = false;
  }

  start(text) {
    this.text   = text;
    this.active = true;
    this._draw();
    this.interval = setInterval(() => this._draw(), 80);
  }

  update(text) {
    this.text = text;
  }

  stop() {
    if (!this.active) return;
    clearInterval(this.interval);
    this.active = false;
    // Clear spinner line so results print on a clean slate
    process.stdout.write('\r\x1b[2K');
  }

  _draw() {
    const f    = SPIN_FRAMES[this.frame++ % SPIN_FRAMES.length];
    const spin = chalk.hex('#00b4d8')(f);
    process.stdout.write(`\r\x1b[2K    ${spin}  ${colors.dim(this.text)}`);
  }
}

// ── Code audit logger ────────────────────────────────────────────────────────
export class AuditLogger {
  constructor({ engine = 'code', depth = 'standard', projectRoot = '' }) {
    this.engine     = engine;
    this.depth      = depth;
    this.project    = path.basename(projectRoot) || projectRoot;
    this.startTime  = null;
    this.spinner    = new LineSpinner();
    this.total      = 0;
    this.done       = 0;
    this.results    = [];
    this._pending   = [];   // module names still running
  }

  start(moduleNames) {
    this.startTime = Date.now();
    this.total     = moduleNames.length;
    this.done      = 0;
    this._pending  = [...moduleNames];

    const engineLabel = this.engine === 'infra'
      ? chalk.hex('#a78bfa').bold('INFRA')
      : chalk.hex('#00f5a0').bold('CODE');
    const depthLabel  = colors.dim(`[${this.depth}]`);
    const proj        = chalk.hex('#a78bfa')(this.project);

    console.log('');
    console.log(`  ${colors.accent('▸')} Audit ${engineLabel} ${depthLabel}  ${proj}`);
    console.log(`  ${divider(50)}`);
    console.log('');

    this.spinner.start(this._statusText());
  }

  moduleComplete(name, result, ms) {
    this.done++;
    this._pending = this._pending.filter(n => n !== name);
    this.results.push({ name, severity: result.severity || 'ok', ms });

    // Stop spinner temporarily to print the result line cleanly
    this.spinner.stop();

    const sev     = SEVERITY[result.severity] || SEVERITY.ok;
    const modName = chalk.hex('#c8d6f0')(name.padEnd(10));
    const timing  = colors.dim(`${ms}ms`);
    const finding = firstFinding(result);
    const msg     = finding
      ? `  ${colors.dim('—')}  ${chalk.hex('#c8d6f0')(truncate(finding, 50))}`
      : '';

    console.log(`    ${sev.color(`${sev.icon} ${sev.label}`)}  ${modName}  ${timing}${msg}`);

    // Restart spinner if there are still pending modules
    if (this._pending.length > 0) {
      this.spinner.start(this._statusText());
    }
  }

  end(riskScore) {
    this.spinner.stop();

    const totalMs = Date.now() - this.startTime;
    const counts  = countBySeverity(this.results);

    console.log('');
    console.log(`  ${divider(50)}`);

    const riskColor = riskScore >= 70
      ? chalk.hex('#ff2d55').bold
      : riskScore >= 40
        ? chalk.hex('#ff9f1c').bold
        : chalk.hex('#00f5a0').bold;

    const dot  = chalk.hex('#3a4560')(' · ');
    const parts = [
      `${colors.dim('risk')} ${riskColor(`${riskScore}/100`)}`,
      counts.critical > 0 ? chalk.hex('#ff2d55').bold(`${counts.critical} critical`) : null,
      counts.high     > 0 ? chalk.hex('#ff9f1c').bold(`${counts.high} high`)         : null,
      counts.medium   > 0 ? chalk.hex('#00b4d8')(`${counts.medium} medium`)          : null,
      counts.low      > 0 ? chalk.hex('#5a6880')(`${counts.low} low`)                : null,
      counts.ok       > 0 ? chalk.hex('#00f5a0')(`${counts.ok} ok`)                  : null,
    ].filter(Boolean);

    const time = colors.dim(`${(totalMs / 1000).toFixed(1)}s`);
    console.log(`  ${colors.accent('▸')} ${parts.join(dot)}  ${time}`);
    console.log('');
  }

  _statusText() {
    const ratio = colors.dim(`${this.done}/${this.total}`);
    const names = this._pending.slice(0, 4).join(', ') +
      (this._pending.length > 4 ? ` +${this._pending.length - 4}` : '');
    return `${ratio}  ${names}`;
  }
}

// ── Infra audit logger ───────────────────────────────────────────────────────
export class InfraLogger {
  constructor(projectRoot = '') {
    this.project   = path.basename(projectRoot) || projectRoot;
    this.startTime = Date.now();
    this.spinner   = new LineSpinner();
  }

  start(modules = []) {
    const label = modules.length > 0 ? `${modules.length} módulos` : 'todos los módulos';

    console.log('');
    console.log(`  ${colors.infra('▸')} Audit ${chalk.hex('#a78bfa').bold('INFRA')}  ${chalk.hex('#a78bfa')(this.project)}`);
    console.log(`  ${divider(50)}`);
    console.log('');

    this.spinner.start(`IronBase Engine  ${colors.dim(label)}`);
  }

  end(result) {
    this.spinner.stop();
    const totalMs  = Date.now() - this.startTime;
    const modules  = result?.modules || [];
    const issues   = modules.filter(m => (m.severity || m.status) !== 'ok').length;
    const time     = colors.dim(`${(totalMs / 1000).toFixed(1)}s`);

    console.log(`    ${chalk.hex('#00f5a0')('✓ OK      ')}  ${colors.text('IronBase Engine')}  ${time}  ${colors.dim(`${modules.length} módulos · ${issues} hallazgos`)}`);
    console.log('');
    console.log(`  ${divider(50)}`);
    console.log(`  ${colors.infra('▸')} Infra audit completado  ${time}`);
    console.log('');
  }

  error(err) {
    this.spinner.stop();
    console.log(`    ${chalk.hex('#ff2d55')('✖ ERROR   ')}  ${colors.text('IronBase Engine')}  ${chalk.hex('#ff2d55')(err.message)}`);
    console.log('');
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function firstFinding(result) {
  const f = result?.findings?.[0];
  if (!f) return null;
  return f.title || f.description || null;
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

function countBySeverity(results) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) c[r.severity] = (c[r.severity] || 0) + 1;
  return c;
}
