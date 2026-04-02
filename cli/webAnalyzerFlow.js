/**
 * Web Analyzer CLI Flow
 * Handles: URL input, animated progress, result display
 */
import readline from 'readline';
import chalk from 'chalk';
import { divider, colors, t, box } from './theme.js';
import { run as runEngine } from '../engines/webAnalyzer.js';

function ask(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

function clearScreen() {
  process.stdout.write('\x1bc');
}

export async function runWebAnalyzerFlow() {
  clearScreen();
  console.log('');
  console.log(box(chalk.bold('Web Analyzer'), { color: '#00b4d8' }));
  console.log(`  ${colors.dim('Identifica el stack tecnológico de un sitio web')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  const target = await ask(colors.accent2('  ▸ ') + colors.text('Target URL (e.g. https://google.com): '));
  if (!target) return;

  let url;
  try {
    url = new URL(target);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
  } catch {
    console.log(`\n  ${t.fail('URL inválida. Asegúrate de incluir http:// o https://')}\n`);
    await ask(colors.dim('  Presiona Enter para volver... '));
    return;
  }

  console.log('');
  const hooks = {
    onPhase: (phase, msg) => {
      process.stdout.write(`\r\x1b[2K  ${chalk.hex('#00b4d8')('◌')} ${colors.dim(msg)}`);
    }
  };

  try {
    const result = await runEngine({ target, hooks });
    process.stdout.write('\r\x1b[2K');
    
    console.log(`  ${chalk.hex('#00f5a0')('✓')} ${colors.text('Análisis completado para')} ${chalk.bold(target)}`);
    console.log(`  ${divider(52)}`);
    console.log('');

    const categories = {
      cms:       { label: 'CMS / Plataforma',    color: '#ff9f1c' },
      framework: { label: 'Frameworks JS',       color: '#a78bfa' },
      ui:        { label: 'UI / Estilos',        color: '#ff2d55' },
      analytics: { label: 'Analíticas / Marketing', color: '#38bdf8' },
      infra:     { label: 'Infraestructura',     color: '#34d399' },
      security:  { label: 'Seguridad',           color: '#ffd60a' },
    };

    let foundAny = false;
    for (const [id, meta] of Object.entries(categories)) {
      const techs = result.technologies[id];
      if (techs && techs.length > 0) {
        foundAny = true;
        console.log(`  ${chalk.hex(meta.color).bold(meta.label)}`);
        for (const t of techs) {
          console.log(`    ${colors.dim('·')} ${chalk.hex('#c8d6f0')(t)}`);
        }
        console.log('');
      }
    }

    if (!foundAny) {
      console.log(`  ${colors.dim('No se detectaron tecnologías específicas.')}`);
      console.log(`  ${colors.dim('HTTP Status:')} ${chalk.hex('#00f5a0')(result.status)}`);
      console.log('');
    } else {
      console.log(`  ${divider(52)}`);
      console.log(`  ${colors.dim('Resumen:')} ${Object.values(result.technologies).flat().length} tecnologías detectadas`);
      console.log('');
    }

  } catch (err) {
    process.stdout.write('\r\x1b[2K');
    console.log(`  ${t.fail('Error en el análisis')}  ${colors.dim(err.message)}`);
    console.log('');
  }

  await ask(colors.dim('  Presiona Enter para volver al menú... '));
}
