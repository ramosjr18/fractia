/**
 * Fractia Web Server — optional UI, started via `fractia serve` or menu option [s]
 * Can also be run directly: node server.js (legacy mode, shows project selector on start)
 */
import express from 'express';
import cors from 'cors';
import path from 'path';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import chalk from 'chalk';

import { config }              from './config.js';
import { discoverStructure }   from './utils/fileScanner.js';
import { isIronbaseAvailable, getInfraModules, runInfraScan } from './engines/ironbaseRunner.js';
import { runCodeAudit, calculateRiskScore, generateSummary, ALL_MODULES } from './engines/codeAudit.js';
import { run as runWebAnalyzer } from './engines/webAnalyzer.js';
import { AuditLogger, InfraLogger } from './cli/auditLogger.js';
import { t, link, divider, logo, colors, box } from './cli/theme.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Express app ──────────────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: /^http:\/\/localhost(:\d+)?$/ }));
app.use(express.json());

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok', version: '3.0.0',
    projectRoot: config.projectRoot,
    aiProvider:  config.aiProvider || 'none',
    engines: { code: true, infra: isIronbaseAvailable() },
  });
});

app.get('/api/structure', async (_req, res) => {
  try   { res.json(await discoverStructure()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/infra-modules', (_req, res) => {
  res.json({ available: isIronbaseAvailable(), modules: getInfraModules() });
});

// ── Concurrent run guards ────────────────────────────────────────────────────
let isCodeRunning  = false;
let isInfraRunning = false;

// ── Code audit endpoint ──────────────────────────────────────────────────────
app.post('/api/audit', async (req, res) => {
  if (isCodeRunning) return res.status(429).json({ error: 'Code audit already in progress.' });

  const { modules = ALL_MODULES, depth = 'standard' } = req.body;
  const validModules = modules.filter(m => ALL_MODULES.includes(m));
  if (!validModules.length) return res.status(400).json({ error: 'No valid modules selected.' });

  isCodeRunning = true;
  const logger  = new AuditLogger({ engine: 'code', depth, projectRoot: config.projectRoot });
  logger.start(validModules);

  try {
    const { results, riskScore, summary, meta } = await runCodeAudit(validModules, depth, {
      onModuleComplete: (mod, result, ms) => logger.moduleComplete(mod, result, ms),
    });

    logger.end(riskScore);
    res.json({ summary, risk_score: riskScore, modules: results, meta });
  } catch (err) {
    console.error('[server] Code audit failed:', err);
    res.status(500).json({ error: err.message });
  } finally {
    isCodeRunning = false;
  }
});

// ── Infra audit endpoint ─────────────────────────────────────────────────────
app.post('/api/infra-audit', async (req, res) => {
  if (isInfraRunning) return res.status(429).json({ error: 'Infra audit already in progress.' });
  if (!isIronbaseAvailable()) return res.status(503).json({ error: 'IronBase engine not available.' });

  const { modules } = req.body;
  isInfraRunning = true;

  const infraLogger = new InfraLogger(config.projectRoot);
  infraLogger.start(modules || []);

  try {
    const result = await runInfraScan(modules);
    infraLogger.end(result);
    res.json(result);
  } catch (err) {
    infraLogger.error(err);
    res.status(500).json({ error: err.message });
  } finally {
    isInfraRunning = false;
  }
});

// ── Web Analyzer endpoint ───────────────────────────────────────────────────
app.post('/api/web-analyzer', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required.' });

  try {
    const result = await runWebAnalyzer({ target });
    res.json(result);
  } catch (err) {
    console.error('[server] Web analyzer failed:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Startup banner ───────────────────────────────────────────────────────────
async function printBanner() {
  const structure    = await discoverStructure();
  const ironbaseUp   = isIronbaseAvailable();
  const uiUrl        = `http://localhost:${config.port}`;
  const providerLabel = {
    claude: t.ok(`Claude (Anthropic) ${colors.dim('— deep/full modes')}`),
    openai: t.ok(`OpenAI (GPT-4o) ${colors.dim('— deep/full modes')}`),
    none:   t.fail('Sin IA'),
  }[config.aiProvider] || t.fail('Sin IA');

  console.log('');
  console.log(logo());
  console.log('');
  console.log(`  ${colors.accent.bold('Full-Stack Security Platform')} ${colors.dim('— v3.0.0')}`);
  console.log(`  ${divider()}`);
  console.log('');
  console.log(`  ${t.label('UI')}           ${link(uiUrl, uiUrl)}`);
  console.log(`  ${t.label('Proyecto')}     ${colors.infra(path.basename(config.projectRoot))} ${colors.dim(config.projectRoot)}`);
  console.log(`  ${t.label('Framework')}    ${colors.text(structure.framework)} ${colors.dim(`(src: ${structure.srcDir})`)}`);
  console.log(`  ${t.label('IA')}           ${providerLabel}`);
  console.log(`  ${t.label('Infra')}        ${ironbaseUp ? t.ok('IronBase Engine detectado') : t.fail('IronBase no disponible')}`);
  console.log('');
  console.log(`  ${divider()}`);
  console.log(`  ${colors.dim('Ctrl+C para detener el servidor')}`);
  console.log('');
}

// ── Exported start function (called from fractia.js menu) ───────────────────
export async function startServer() {
  return new Promise((resolve) => {
    app.listen(config.port, async () => {
      await printBanner();
      resolve();
    });
  });
}

// ── Legacy direct mode: node server.js ──────────────────────────────────────
// If run directly (not imported), behave like fractia with just the serve flow
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  // Redirect to the full CLI entrypoint
  console.log('');
  console.log(chalk.hex('#00b4d8')('  ▸ Usa `node fractia.js` para el CLI completo, o `node fractia.js serve` para solo la web.'));
  console.log('');

  // Still start the server for backwards compatibility
  import('./cli/projectSelector.js').then(async ({ selectProject, addToHistory }) => {
    import('./cli/configStore.js').then(async ({ store }) => {
      import('readline').then(async (rl) => {
        const { existsSync } = await import('fs');

        const cliArg = process.argv[2];
        if (cliArg && cliArg !== '--') {
          const resolved = path.resolve(cliArg);
          if (!existsSync(resolved)) {
            console.log(t.fail(`Ruta no existe: ${resolved}`)); process.exit(1);
          }
          config.projectRoot = resolved;
          addToHistory(resolved);
        } else {
          config.projectRoot = await selectProject(process.env.PROJECT_ROOT || '');
        }

        const savedAI = store.get('aiProvider');
        if (savedAI && !config.aiProvider) config.aiProvider = savedAI;

        await startServer();
      });
    });
  });
}
