#!/usr/bin/env node
/**
 * Fractia CLI — primary entrypoint
 * Usage:
 *   fractia                                          → interactive menu
 *   fractia serve                                    → start web UI server
 *   fractia attack --target URL --profile PROFILE    → DAST attack (direct)
 *     Profiles: recon | spike-test | slowloris | bots-stuffing | form-flood
 *     Options:  --login-path PATH  --requests N  --duration N  --body TEMPLATE
 *               --mode MODE  (form-flood: flood|user-enum|stuffing|spam|inject|all)
 *               --method GET|POST  (spike-test)
 *               --form-action URL  --fields "name,email,message"  (form-flood SPA)
 */
import path from 'path';
import readline from 'readline';
import { fileURLToPath } from 'url';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import chalk from 'chalk';

import { config }              from './config.js';
import { discoverStructure }   from './utils/fileScanner.js';
import { isIronbaseAvailable } from './engines/ironbaseRunner.js';
import { runCodeAudit, ALL_MODULES } from './engines/codeAudit.js';
import { runInfraScan }        from './engines/ironbaseRunner.js';
import { runMobileAudit, MOBILE_MODULES, isMobileProject } from './engines/flutterRunner.js';

import { logo, divider, box, link, t, colors } from './cli/theme.js';
import { selectProject, addToHistory }          from './cli/projectSelector.js';
import { AuditLogger, InfraLogger }             from './cli/auditLogger.js';
import { renderResults, promptDetailView }      from './cli/resultRenderer.js';
import { store }                                from './cli/configStore.js';
import { runAttackCLI, runAttackInteractive }   from './cli/attackFlow.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Report export ────────────────────────────────────────────────────────────
function saveReport({ engine, results, riskScore, summary, meta }) {
  const reportsDir = path.join(__dirname, 'reports');
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });

  const ts       = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const project  = path.basename(config.projectRoot);
  const filename = `${project}_${engine}_${ts}.json`;
  const filepath = path.join(reportsDir, filename);

  const report = {
    meta: { ...meta, exportedAt: new Date().toISOString(), tool: 'Fractia v3.0.0' },
    summary,
    risk_score: riskScore,
    modules: results,
  };

  writeFileSync(filepath, JSON.stringify(report, null, 2), 'utf8');
  return filepath;
}

// ── readline helper ──────────────────────────────────────────────────────────
function ask(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

function clearScreen() {
  process.stdout.write('\x1bc');
}

// ── AI provider setup (only if not already set) ──────────────────────────────
async function ensureAIProvider() {
  if (config.aiProvider) return;

  const { readFileSync, writeFileSync } = await import('fs');
  function saveToEnv(key, value) {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    try { content = readFileSync(envPath, 'utf8'); } catch {}
    const lines = content.split('\n');
    const idx = lines.findIndex(l => l.startsWith(`${key}=`));
    if (idx >= 0) lines[idx] = `${key}=${value}`; else lines.push(`${key}=${value}`);
    writeFileSync(envPath, lines.join('\n'), 'utf8');
  }

  console.log('');
  console.log(box(chalk.bold('Enriquecimiento con IA'), { color: '#00b4d8' }));
  console.log('');
  console.log(t.option('[1]', `Claude ${colors.dim('(Anthropic)')}`));
  console.log(t.option('[2]', `OpenAI  ${colors.dim('(GPT-4o)')}`));
  console.log(t.option('[3]', `Sin IA  ${colors.dim('— solo análisis estático')}`));
  console.log('');

  const ans    = await ask(colors.accent2('  ▸ ') + colors.text('Proveedor [1/2/3]: '));
  const choice = ans === '2' ? 'openai' : ans === '3' ? 'none' : 'claude';

  if (choice === 'claude' && !config.anthropicApiKey) {
    const key = await ask(colors.accent2('  ▸ ') + colors.text('ANTHROPIC_API_KEY: '));
    if (key) { config.anthropicApiKey = key; saveToEnv('ANTHROPIC_API_KEY', key); }
    else { config.aiProvider = 'none'; return; }
  }
  if (choice === 'openai' && !config.openaiApiKey) {
    const key = await ask(colors.accent2('  ▸ ') + colors.text('OPENAI_API_KEY: '));
    if (key) { config.openaiApiKey = key; saveToEnv('OPENAI_API_KEY', key); }
    else { config.aiProvider = 'none'; return; }
  }

  config.aiProvider = choice;
  store.set('aiProvider', choice);
}

// ── Header bar (compact, shown above every screen) ───────────────────────────
function printHeader() {
  const proj  = chalk.hex('#a78bfa').bold(path.basename(config.projectRoot));
  const ai    = config.aiProvider && config.aiProvider !== 'none'
    ? chalk.hex('#00f5a0')(config.aiProvider)
    : colors.dim('sin IA');
  const mode  = colors.dim(`[${store.get('defaultDepth')}]`);
  const out   = colors.dim(`[${store.get('outputMode')}]`);

  console.log('');
  console.log(logo());
  console.log('');
  console.log(
    `  ${colors.dim('proyecto')} ${proj}  ` +
    `${colors.dim('ia')} ${ai}  ` +
    `${mode}  ${out}`
  );
  console.log(`  ${divider(52)}`);
}

// ── Main menu ────────────────────────────────────────────────────────────────
async function mainMenu() {
  clearScreen();
  printHeader();

  const ironbase = isIronbaseAvailable();

  console.log('');
  console.log(t.option('[1]', `Code Audit          ${colors.dim(`${ALL_MODULES.length} módulos disponibles`)}`));
  console.log(t.option('[2]', `Infra Audit         ${ironbase ? colors.dim('IronBase listo') : chalk.hex('#ff2d55')('IronBase no disponible')}`));
  console.log(t.option('[3]', `Attack  ${chalk.hex('#ff9f1c').bold('DAST')}         ${colors.dim('recon · spike-test · slowloris · bots-stuffing · form-flood')}`));
  console.log(t.option('[4]', `Mobile Audit  ${chalk.hex('#34d399').bold('Flutter')}  ${colors.dim('10 módulos · auth · crypto · network · storage · …')}`));
  console.log(t.option('[c]', `Configuración`));
  console.log(t.option('[s]', `Iniciar Web UI      ${colors.dim(`http://localhost:${config.port}`)}`));
  console.log(t.option('[p]', `Cambiar proyecto    ${colors.dim(config.projectRoot)}`));
  console.log(t.option('[q]', `Salir`));
  console.log('');

  const ans = await ask(colors.accent2('  ▸ ') + colors.text('Acción: '));

  switch (ans.toLowerCase()) {
    case '1': return codeAuditFlow();
    case '2': return infraAuditFlow();
    case '3': return attackFlow();
    case '4': return mobileAuditFlow();
    case 'c': return configMenu();
    case 's': return serveFlow();
    case 'p': return changeProjectFlow();
    case 'q': case 'quit': case 'exit':
      console.log(''); console.log(`  ${t.dim('Hasta luego.')}`); console.log('');
      process.exit(0);
    default:
      return mainMenu();
  }
}

// ── Code Audit flow ──────────────────────────────────────────────────────────
async function codeAuditFlow() {
  clearScreen();
  printHeader();

  // Module selection
  console.log('');
  console.log(`  ${colors.accent2('Code Audit')}  ${colors.dim('— selección de módulos')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  const groups = [
    { label: 'Auth & API',    mods: ['auth', 'api', 'headers'] },
    { label: 'Inyecciones',   mods: ['sql', 'xss', 'secrets'] },
    { label: 'Disponibilidad',mods: ['ddos', 'bots', 'deps'] },
    { label: 'Infraestructura',mods: ['infra', 'crypto', 'logs', 'nextjs'] },
  ];

  let optNum = 1;
  const groupMap = {};
  for (const g of groups) {
    console.log(`  ${colors.accent2(g.label)}`);
    console.log(t.option(`[${optNum}]`, g.mods.join(', ')));
    groupMap[optNum] = g.mods;
    optNum++;
  }
  console.log('');
  console.log(t.option(`[${optNum}]`, `Todos los módulos  ${colors.dim(`(${ALL_MODULES.length} total)`)}`));
  groupMap[optNum] = ALL_MODULES;
  console.log('');

  const modAns = await ask(colors.accent2('  ▸ ') + colors.text(`Módulos [1-${optNum}]: `));
  const modChoice = parseInt(modAns, 10);
  const selectedMods = groupMap[modChoice] || ALL_MODULES;

  // Depth selection
  console.log('');
  console.log(`  ${colors.dim('profundidad de análisis')}`);
  console.log(t.option('[1]', `Standard  ${colors.dim('— análisis estático rápido')}`));
  console.log(t.option('[2]', `Deep      ${colors.dim('— estático + AI analiza vulnerabilidades')}`));
  console.log(t.option('[3]', `Full      ${colors.dim('— deep + AI construye cadenas de ataque')}`));
  console.log('');

  const depthAns = await ask(colors.accent2('  ▸ ') + colors.text('Depth [1/2/3]: '));
  const depth    = depthAns === '2' ? 'deep' : depthAns === '3' ? 'full' : 'standard';

  // Ensure AI if needed
  if (depth !== 'standard') await ensureAIProvider();

  // Run with live logger
  const logger = new AuditLogger({ engine: 'code', depth, projectRoot: config.projectRoot });
  logger.start(selectedMods);

  const { results, riskScore, summary, meta } = await runCodeAudit(selectedMods, depth, {
    onModuleComplete: (mod, result, ms) => logger.moduleComplete(mod, result, ms),
  });

  logger.end(riskScore);

  // Render results
  const outputMode = store.get('outputMode');
  renderResults(results, { mode: outputMode, riskScore });

  if (outputMode === 'compact') {
    await promptDetailView(results);
  }

  // Save JSON report
  const reportPath = saveReport({ engine: 'code', results, riskScore, summary, meta });
  const reportUrl  = `file://${reportPath}`;
  console.log(`  ${colors.accent('▸')} Reporte guardado  ${link(path.basename(reportPath), reportUrl)}`);
  console.log(`    ${colors.dim(reportPath)}`);
  console.log('');

  await ask(colors.dim('  Pulsa Enter para volver al menú... '));
  return mainMenu();
}

// ── Infra Audit flow ─────────────────────────────────────────────────────────
async function infraAuditFlow() {
  if (!isIronbaseAvailable()) {
    console.log('');
    console.log(t.fail('IronBase Engine no disponible. Verifica engines/ironbase/'));
    console.log('');
    await ask(colors.dim('  Enter para volver... '));
    return mainMenu();
  }

  clearScreen();
  printHeader();
  console.log('');
  console.log(`  ${colors.infra('Infra Audit')}  ${colors.dim('— IronBase Engine')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  const infraLogger = new InfraLogger(config.projectRoot);
  infraLogger.start([]);

  try {
    const result = await runInfraScan();
    infraLogger.end(result);

    // Save JSON report
    const infraResults = result?.modules || [];
    const reportPath = saveReport({
      engine: 'infra',
      results: infraResults,
      riskScore: result?.risk_score ?? 0,
      summary: result?.summary ?? '',
      meta: { engine: 'infra', projectRoot: config.projectRoot, generatedAt: new Date().toISOString() },
    });
    const reportUrl = `file://${reportPath}`;
    console.log(`  ${colors.infra('▸')} Reporte guardado  ${link(path.basename(reportPath), reportUrl)}`);
    console.log(`    ${colors.dim(reportPath)}`);
    console.log('');
  } catch (err) {
    infraLogger.error(err);
  }

  await ask(colors.dim('  Pulsa Enter para volver al menú... '));
  return mainMenu();
}

// ── Config menu ──────────────────────────────────────────────────────────────
async function configMenu() {
  clearScreen();
  printHeader();

  const cfg = store.all();

  console.log('');
  console.log(`  ${colors.accent2('Configuración')}`);
  console.log(`  ${divider(52)}`);
  console.log('');
  console.log(t.option('[1]', `Output mode     ${colors.accent(cfg.outputMode)}`));
  console.log(t.option('[2]', `Depth default   ${colors.accent(cfg.defaultDepth)}`));
  console.log(t.option('[3]', `IA provider     ${colors.accent(cfg.aiProvider || 'no configurado')}`));
  console.log(t.option('[b]', `Volver`));
  console.log('');

  const ans = await ask(colors.accent2('  ▸ ') + colors.text('Opción: '));

  if (ans === '1') {
    const cur  = cfg.outputMode;
    const next = cur === 'expanded' ? 'compact' : 'expanded';
    store.set('outputMode', next);
    console.log(`  ${t.ok(`Output mode → ${next}`)}`);
    await ask(colors.dim('  Enter para continuar... '));
    return configMenu();
  }

  if (ans === '2') {
    console.log('');
    console.log(t.option('[1]', 'standard'));
    console.log(t.option('[2]', 'deep'));
    console.log(t.option('[3]', 'full'));
    const d = await ask(colors.accent2('  ▸ ') + colors.text('Depth [1/2/3]: '));
    const depth = d === '2' ? 'deep' : d === '3' ? 'full' : 'standard';
    store.set('defaultDepth', depth);
    console.log(`  ${t.ok(`Default depth → ${depth}`)}`);
    await ask(colors.dim('  Enter para continuar... '));
    return configMenu();
  }

  if (ans === '3') {
    config.aiProvider = '';
    await ensureAIProvider();
    return configMenu();
  }

  return mainMenu();
}

// ── Web server flow ──────────────────────────────────────────────────────────
async function serveFlow() {
  clearScreen();
  printHeader();
  console.log('');
  console.log(`  ${colors.accent('▸')} Iniciando Web UI...`);
  console.log('');

  // Dynamically import and start the express server
  const { startServer } = await import('./server.js');
  await startServer();
}

// ── Change project flow ──────────────────────────────────────────────────────
async function changeProjectFlow() {
  const { readFileSync, writeFileSync } = await import('fs');

  function saveToEnv(key, value) {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    try { content = readFileSync(envPath, 'utf8'); } catch {}
    const lines = content.split('\n');
    const idx = lines.findIndex(l => l.startsWith(`${key}=`));
    if (idx >= 0) lines[idx] = `${key}=${value}`; else lines.push(`${key}=${value}`);
    writeFileSync(envPath, lines.join('\n'), 'utf8');
  }

  const newPath = await selectProject(config.projectRoot);
  config.projectRoot = newPath;
  saveToEnv('PROJECT_ROOT', newPath);
  return mainMenu();
}

// ── Mobile Audit flow (Pilar D: Flutter/Dart) ────────────────────────────────
async function mobileAuditFlow() {
  clearScreen();
  printHeader();

  console.log('');
  console.log(`  ${chalk.hex('#34d399').bold('Mobile Audit')}  ${colors.dim('— Flutter/Dart Security Engine')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  // ── 1. Flutter project path ───────────────────────────────────────────────
  const defaultRoot = config.projectRoot;
  const isMobile    = isMobileProject(defaultRoot);

  if (isMobile) {
    console.log(`  ${colors.dim('Proyecto Flutter detectado:')} ${chalk.hex('#34d399')(path.basename(defaultRoot))}`);
    console.log('');
  } else {
    console.log(`  ${colors.dim('El proyecto actual no parece ser Flutter (falta pubspec.yaml o lib/).')}`);
    console.log(`  ${colors.dim('Introduce la ruta al proyecto Flutter a analizar:')}`);
    console.log('');
  }

  let flutterRoot = defaultRoot;
  if (!isMobile) {
    const ans = await ask(colors.accent2('  ▸ ') + colors.text(`Ruta Flutter [${defaultRoot}]: `));
    if (ans) flutterRoot = path.resolve(ans);
    if (!isMobileProject(flutterRoot)) {
      console.log('');
      console.log(`  ${chalk.hex('#ff2d55')('✗')} No se encontró pubspec.yaml + lib/ en: ${flutterRoot}`);
      console.log(`  ${colors.dim('Puedes igualmente continuar y los módulos que apliquen reportarán resultados.')}`);
      console.log('');
    }
  }

  // ── 2. Module selection ───────────────────────────────────────────────────
  const MODULE_GROUPS = [
    { label: 'Auth & Storage',  mods: ['auth', 'storage'] },
    { label: 'Red & Crypto',    mods: ['network', 'crypto'] },
    { label: 'App & Links',     mods: ['platform', 'deeplinks'] },
    { label: 'Build & Código',  mods: ['deps', 'obfuscation', 'logging', 'state'] },
  ];

  console.log(`  ${colors.dim('selección de módulos')}`);
  console.log('');

  let optNum = 1;
  const groupMap = {};
  for (const g of MODULE_GROUPS) {
    console.log(`  ${colors.accent2(g.label)}`);
    console.log(t.option(`[${optNum}]`, g.mods.join(', ')));
    groupMap[optNum] = g.mods;
    optNum++;
  }
  console.log('');
  console.log(t.option(`[${optNum}]`, `Todos los módulos  ${colors.dim(`(${MOBILE_MODULES.length} total)`)}`));
  groupMap[optNum] = MOBILE_MODULES;
  console.log('');

  const modAns     = await ask(colors.accent2('  ▸ ') + colors.text(`Módulos [1-${optNum}]: `));
  const modChoice  = parseInt(modAns, 10);
  const selectedMods = groupMap[modChoice] || MOBILE_MODULES;

  // ── 3. Live logger ────────────────────────────────────────────────────────
  clearScreen();
  printHeader();
  console.log('');
  console.log(`  ${chalk.hex('#34d399').bold('Mobile Audit')}  ${colors.dim(`→ ${path.basename(flutterRoot)}`)}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  const SEV_COLOR = {
    critical: chalk.hex('#ff2d55').bold,
    high:     chalk.hex('#ff9f1c').bold,
    medium:   chalk.hex('#ffd60a'),
    low:      chalk.hex('#48cae4'),
    ok:       chalk.hex('#34d399'),
  };
  const SEV_ICON = { critical: '✗', high: '!', medium: '~', low: '·', ok: '✓' };

  const hooks = {
    onModuleStart({ name, index, total }) {
      process.stdout.write(
        `  ${colors.dim(`[${String(index + 1).padStart(2)}/${total}]`)} ` +
        `${colors.accent('◌')} ${colors.text(name)}…\r`
      );
    },
    onModuleComplete({ name, result, index, total, ms }) {
      const sev  = result.severity || 'ok';
      const icon = SEV_ICON[sev] || '·';
      const col  = SEV_COLOR[sev] || (x => x);
      const cnt  = result.findings?.length || 0;
      const fStr = cnt > 0 ? colors.dim(` — ${cnt} hallazgo${cnt > 1 ? 's' : ''}`) : '';
      process.stdout.write('\x1b[2K'); // clear line
      console.log(
        `  ${colors.dim(`[${String(index + 1).padStart(2)}/${total}]`)} ` +
        `${col(icon)} ${colors.text(name)}${fStr}  ${colors.dim(`${ms}ms`)}`
      );
    },
  };

  let auditResult;
  try {
    auditResult = await runMobileAudit(selectedMods, flutterRoot, hooks);
  } catch (err) {
    console.log('');
    console.log(`  ${chalk.hex('#ff2d55')('✗ Error ejecutando Mobile Audit:')} ${err.message}`);
    console.log(`  ${colors.dim(err.stack?.split('\n')[1] || '')}`);
    console.log('');
    await ask(colors.dim('  Enter para volver al menú... '));
    return mainMenu();
  }

  // ── 4. Summary ────────────────────────────────────────────────────────────
  const { worstSeverity, totalFindings, counts, riskScore, dartFilesScanned } = auditResult;

  console.log('');
  console.log(`  ${divider(52)}`);
  console.log('');

  // Risk score bar
  const barLen  = 30;
  const filled  = Math.round((riskScore / 100) * barLen);
  const barCol  = riskScore >= 70 ? chalk.hex('#ff2d55') : riskScore >= 40 ? chalk.hex('#ff9f1c') : chalk.hex('#34d399');
  const bar     = barCol('█'.repeat(filled)) + colors.dim('░'.repeat(barLen - filled));
  console.log(`  ${colors.dim('Risk Score')}  ${bar}  ${barCol.bold(riskScore + '/100')}`);
  console.log('');

  // Severity counts
  const sevLine = ['critical', 'high', 'medium', 'low', 'ok']
    .filter(s => (counts[s] || 0) > 0)
    .map(s => `${SEV_COLOR[s](SEV_ICON[s])} ${SEV_COLOR[s](s)} ${colors.dim('×' + counts[s])}`)
    .join('   ');
  if (sevLine) console.log(`  ${sevLine}`);
  console.log('');
  console.log(`  ${colors.dim('Archivos Dart escaneados:')} ${chalk.hex('#a78bfa')(dartFilesScanned)}`);
  console.log(`  ${colors.dim('Hallazgos totales:')}       ${totalFindings > 0 ? chalk.hex('#ff9f1c').bold(totalFindings) : chalk.hex('#34d399').bold(totalFindings)}`);
  console.log('');

  // ── 5. Findings detail ────────────────────────────────────────────────────
  const outputMode = store.get('outputMode');

  if (outputMode === 'expanded') {
    for (const r of auditResult.results) {
      if (!r.findings?.length) continue;
      const sev = r.severity || 'ok';
      console.log(`  ${SEV_COLOR[sev].bold(`[${r.name}]`)}  ${colors.dim(r.summary)}`);
      for (const f of r.findings) {
        const fc = SEV_COLOR[f.severity] || (x => x);
        console.log(`    ${fc(SEV_ICON[f.severity] || '·')} ${fc.bold(f.title)}`);
        if (f.file)        console.log(`      ${colors.dim('file')}  ${colors.accent(f.file)}${f.line ? colors.dim(':' + f.line) : ''}`);
        if (f.description) console.log(`      ${colors.dim(f.description)}`);
        if (f.fix)         console.log(`      ${chalk.hex('#34d399')('fix')}   ${f.fix}`);
        if (f.cve)         console.log(`      ${colors.dim('ref')}   ${colors.dim(f.cve)}`);
        if (f.code)        console.log(`      ${colors.dim('›')} ${chalk.hex('#a78bfa')(f.code.trim())}`);
        console.log('');
      }
    }
  } else {
    // Compact: one line per finding (critical+high only expanded)
    for (const r of auditResult.results) {
      if (!r.findings?.length) continue;
      for (const f of r.findings) {
        const fc = SEV_COLOR[f.severity] || (x => x);
        const loc = f.file ? colors.dim(` — ${f.file}${f.line ? ':' + f.line : ''}`) : '';
        console.log(`  ${fc(SEV_ICON[f.severity])} ${fc(f.title)}${loc}`);
        if (['critical', 'high'].includes(f.severity)) {
          if (f.fix) console.log(`    ${chalk.hex('#34d399')('▸')} ${f.fix}`);
        }
      }
    }
    console.log('');
  }

  // ── 6. Save JSON report ───────────────────────────────────────────────────
  const reportsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'reports');
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });

  const ts         = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const projName   = path.basename(flutterRoot);
  const filename   = `${projName}_mobile_${ts}.json`;
  const reportPath = path.join(reportsDir, filename);

  const report = {
    meta: {
      engine:      'flutter',
      projectRoot: flutterRoot,
      modules:     selectedMods,
      generatedAt: new Date().toISOString(),
      tool:        'Fractia v3.0.0',
    },
    summary: {
      riskScore,
      worstSeverity,
      totalFindings,
      dartFilesScanned,
      counts,
    },
    risk_score: riskScore,
    modules: auditResult.results,
  };

  writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
  const reportUrl = `file://${reportPath}`;
  console.log(`  ${chalk.hex('#34d399')('▸')} Reporte guardado  ${link(path.basename(reportPath), reportUrl)}`);
  console.log(`    ${colors.dim(reportPath)}`);
  console.log('');

  await ask(colors.dim('  Pulsa Enter para volver al menú... '));
  return mainMenu();
}

// ── Attack flow (Pilar C: DAST) ───────────────────────────────────────────────
async function attackFlow() {
  clearScreen();
  printHeader();
  await runAttackInteractive();
  await ask(colors.dim('  Pulsa Enter para volver al menú... '));
  return mainMenu();
}

// ── Bootstrap ────────────────────────────────────────────────────────────────
async function main() {
  const cliArg = process.argv[2];

  // Show logo first — always, before anything else
  clearScreen();
  console.log('');
  console.log(logo());
  console.log('');
  console.log(`  ${colors.accent.bold('Full-Stack Security Platform')} ${colors.dim('— v3.0.0')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  if (cliArg === 'serve') {
    return serveFlow();
  }

  // fractia attack --target URL --profile PROFILE [--login-path PATH ...]
  if (cliArg === 'attack') {
    const argv = process.argv.slice(3);
    const getFlag = (flag) => {
      const i = argv.indexOf(flag);
      return i !== -1 ? argv[i + 1] : undefined;
    };
    const target  = getFlag('--target');
    const profile = getFlag('--profile');
    if (!target || !profile) {
      console.log('');
      console.log(t.fail('Uso: fractia attack --target URL --profile PROFILE'));
      console.log(`  ${colors.dim('Perfiles: slowloris, bots-stuffing')}`);
      console.log('');
      process.exit(1);
    }
    const optsRaw = {
      loginPath:    getFlag('--login-path'),
      bodyTemplate: getFlag('--body'),
      mode:         getFlag('--mode'),
      formIndex:    getFlag('--form-index') ? parseInt(getFlag('--form-index'), 10) : undefined,
      requests:     getFlag('--requests')   ? parseInt(getFlag('--requests'), 10)   : undefined,
      duration:     getFlag('--duration')   ? parseInt(getFlag('--duration'), 10)   : undefined,
      connections:  getFlag('--connections') ? parseInt(getFlag('--connections'), 10) : undefined,
      formAction:   getFlag('--form-action'),
      fields:       getFlag('--fields'),
      method:       getFlag('--method'),
    };
    // Strip undefined values so engine defaults (meta.defaultOpts) are not overridden
    const opts = Object.fromEntries(Object.entries(optsRaw).filter(([, v]) => v !== undefined));
    await runAttackCLI({ target, profile, opts });
    process.exit(0);
  }

  if (cliArg && cliArg !== '--') {
    const { existsSync } = await import('fs');
    const resolved = path.resolve(cliArg);
    if (!existsSync(resolved)) {
      console.log(t.fail(`Ruta no existe: ${resolved}`));
      process.exit(1);
    }
    config.projectRoot = resolved;
    addToHistory(resolved);
  } else {
    const envRoot = process.env.PROJECT_ROOT || '';
    config.projectRoot = await selectProject(envRoot);
    const { writeFileSync, readFileSync } = await import('fs');
    const envPath = path.join(__dirname, '.env');
    let content = '';
    try { content = readFileSync(envPath, 'utf8'); } catch {}
    const lines = content.split('\n');
    const idx = lines.findIndex(l => l.startsWith('PROJECT_ROOT='));
    if (idx >= 0) lines[idx] = `PROJECT_ROOT=${config.projectRoot}`;
    else lines.push(`PROJECT_ROOT=${config.projectRoot}`);
    writeFileSync(envPath, lines.join('\n'), 'utf8');
  }

  // Restore AI provider from config store if available
  const savedAI = store.get('aiProvider');
  if (savedAI && !config.aiProvider) config.aiProvider = savedAI;

  await mainMenu();
}

main().catch(err => {
  console.error(chalk.hex('#ff2d55')('Error fatal:'), err.message);
  process.exit(1);
});
