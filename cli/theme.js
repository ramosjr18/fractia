/**
 * Fractia CLI Theme — matches web UI color palette
 * Uses chalk with hex colors for true-color terminal output
 */
import chalk from 'chalk';

// ── Core palette (from index.html CSS variables) ────────────────────────────
export const colors = {
  accent:    chalk.hex('#00f5a0'),   // --accent  (bright green)
  accent2:   chalk.hex('#00b4d8'),   // --accent2 (cyan)
  warn:      chalk.hex('#ff9f1c'),   // --warn    (orange)
  danger:    chalk.hex('#ff2d55'),   // --danger  (red)
  infra:     chalk.hex('#a78bfa'),   // --infra   (purple)
  text:      chalk.hex('#c8d6f0'),   // --text    (light blue-gray)
  dim:       chalk.hex('#5a6880'),   // --text-dim
  muted:     chalk.hex('#3a4560'),   // --muted
  white:     chalk.white,
  bold:      chalk.bold,
};

// ── Semantic aliases ────────────────────────────────────────────────────────
export const t = {
  // Headings & emphasis
  title:     (s) => chalk.bold.hex('#00f5a0')(s),
  subtitle:  (s) => chalk.hex('#c8d6f0')(s),
  heading:   (s) => chalk.bold.hex('#00b4d8')(s),

  // Status indicators
  ok:        (s) => chalk.hex('#00f5a0')(`✓ ${s}`),
  fail:      (s) => chalk.hex('#ff2d55')(`✗ ${s}`),
  warn:      (s) => chalk.hex('#ff9f1c')(`⚠ ${s}`),
  info:      (s) => chalk.hex('#00b4d8')(`● ${s}`),

  // Labels & values
  label:     (s) => chalk.hex('#5a6880')(s),
  value:     (s) => chalk.hex('#c8d6f0')(s),
  highlight: (s) => chalk.bold.hex('#00f5a0')(s),
  path:      (s) => chalk.hex('#a78bfa')(s),

  // Interactive
  prompt:    (s) => chalk.hex('#00b4d8')(s),
  option:    (n, s) => `  ${chalk.bold.hex('#00f5a0')(n)}  ${chalk.hex('#c8d6f0')(s)}`,
  selected:  (s) => chalk.bold.hex('#00f5a0')(`▸ ${s}`),
  dim:       (s) => chalk.hex('#3a4560')(s),
};

// ── Clickable hyperlink (OSC 8 escape sequence) ────────────────────────────
// Works in iTerm2, Hyper, Windows Terminal, GNOME Terminal, etc.
export function link(text, url) {
  return `\x1b]8;;${url}\x07${chalk.underline.hex('#00b4d8')(text)}\x1b]8;;\x07`;
}

// ── Box drawing ─────────────────────────────────────────────────────────────
export function box(text, { padding = 2, color = '#00f5a0' } = {}) {
  const pad = ' '.repeat(padding);
  const inner = `${pad}${text}${pad}`;
  const width = stripAnsi(inner).length + 2;
  const c = chalk.hex(color);
  const top    = c('┌' + '─'.repeat(width - 2) + '┐');
  const mid    = c('│') + inner + c('│');
  const bottom = c('└' + '─'.repeat(width - 2) + '┘');
  return `${top}\n${mid}\n${bottom}`;
}

// ── Divider line ────────────────────────────────────────────────────────────
export function divider(width = 45) {
  return chalk.hex('#00f5a0')('─'.repeat(width));
}

// ── Strip ANSI codes for length calculation ─────────────────────────────────
function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*m|\x1b\]8;;[^\x07]*\x07/g, '');
}

// ── ASCII Logo with gradient colors ─────────────────────────────────────────
export function logo() {
  const g1 = chalk.hex('#00f5a0');  // green
  const g2 = chalk.hex('#00d98e');
  const g3 = chalk.hex('#00bd7c');
  const g4 = chalk.hex('#00b4d8');  // transitions to cyan
  const g5 = chalk.hex('#0098c4');
  const g6 = chalk.hex('#a78bfa');  // ends in purple

  return [
    g1('  ███████╗██████╗  █████╗  ██████╗████████╗██╗ █████╗'),
    g2('  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔══██╗'),
    g3('  █████╗  ██████╔╝███████║██║        ██║   ██║███████║'),
    g4('  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║██╔══██║'),
    g5('  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ██║██║  ██║'),
    g6('  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝╚═╝  ╚═╝'),
  ].join('\n');
}
