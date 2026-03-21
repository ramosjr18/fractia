import express from 'express';
import cors from 'cors';
import path from 'path';
import readline from 'readline';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { config } from './config.js';
import { enrichWithClaude } from './utils/claudeClient.js';
import { enrichWithOpenAI } from './utils/openaiClient.js';
import { discoverStructure } from './utils/fileScanner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors({ origin: /^http:\/\/localhost(:\d+)?$/ }));
app.use(express.json());

// Serve the HTML UI
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    projectRoot: config.projectRoot,
    aiProvider: config.aiProvider || 'none',
  });
});

app.get('/api/structure', async (_req, res) => {
  try {
    const struct = await discoverStructure();
    res.json(struct);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Track concurrent runs
let isRunning = false;

// ── Auditor registry ────────────────────────────────────────────────────────
const AUDITORS = {
  auth:    () => import('./auditors/auth.js'),
  api:     () => import('./auditors/api.js'),
  ddos:    () => import('./auditors/ddos.js'),
  sql:     () => import('./auditors/sql.js'),
  xss:     () => import('./auditors/xss.js'),
  secrets: () => import('./auditors/secrets.js'),
  headers: () => import('./auditors/headers.js'),
  deps:    () => import('./auditors/deps.js'),
  infra:   () => import('./auditors/infra.js'),
  bots:    () => import('./auditors/bots.js'),
  crypto:  () => import('./auditors/crypto.js'),
  logs:    () => import('./auditors/logs.js'),
};

// ── Risk score calculation ──────────────────────────────────────────────────
function calculateRiskScore(results) {
  const WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, ok: 0 };
  const total = results.reduce((sum, r) => sum + (WEIGHTS[r.severity] || 0), 0);
  return Math.min(100, total);
}

function generateSummary(results, riskScore) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) counts[r.severity] = (counts[r.severity] || 0) + 1;

  const criticalMods = results.filter(r => r.severity === 'critical').map(r => r.name);
  const highMods     = results.filter(r => r.severity === 'high').map(r => r.name);

  let summary = `Risk score ${riskScore}/100 across ${results.length} modules. `;

  if (counts.critical > 0) {
    summary += `CRITICAL issues in: ${criticalMods.join(', ')}. `;
  }
  if (counts.high > 0) {
    summary += `HIGH severity in: ${highMods.join(', ')}. `;
  }
  if (counts.critical === 0 && counts.high === 0) {
    summary += 'No critical or high severity issues detected. ';
  }

  summary += `${counts.ok} modules passed cleanly.`;
  return summary;
}

// ── Main audit endpoint ─────────────────────────────────────────────────────
app.post('/api/audit', async (req, res) => {
  if (isRunning) {
    return res.status(429).json({ error: 'An audit is already in progress. Please wait.' });
  }

  const { modules = Object.keys(AUDITORS), depth = 'standard' } = req.body;
  const validModules = modules.filter(m => AUDITORS[m]);

  if (validModules.length === 0) {
    return res.status(400).json({ error: 'No valid modules selected.' });
  }

  isRunning = true;
  const startTime = Date.now();

  try {
    // Phase 1: Run all selected auditors in parallel
    const auditResults = await Promise.all(
      validModules.map(async (mod) => {
        try {
          const { audit } = await AUDITORS[mod]();
          return await audit(depth);
        } catch (err) {
          console.error(`[${mod}] Auditor error:`, err.message);
          return {
            id: mod,
            name: mod,
            severity: 'low',
            score: 100,
            findings: [{ type: 'info', title: 'Auditor encountered an error', description: err.message, code_example: null, cve: null }],
            recommendations: [],
            _error: true,
          };
        }
      })
    );

    // Phase 2: Enrich with AI (deep/full modes only, if a provider is selected)
    const aiActive = depth !== 'standard' && config.aiProvider && config.aiProvider !== 'none';
    if (aiActive) {
      try {
        if (config.aiProvider === 'openai') await enrichWithOpenAI(auditResults, depth);
        else if (config.aiProvider === 'claude') await enrichWithClaude(auditResults, depth);
      } catch (err) {
        console.warn(`[${config.aiProvider}] Enrichment failed:`, err.message);
      }
    }

    // Phase 3: Build final response — strip internal fields
    const cleanResults = auditResults.map(({ _codeSnippets, _error, ...r }) => r);
    const riskScore    = calculateRiskScore(cleanResults);
    const summary      = generateSummary(cleanResults, riskScore);

    res.json({
      summary,
      risk_score: riskScore,
      modules: cleanResults,
      meta: {
        generatedAt:    new Date().toISOString(),
        depth,
        projectRoot:    config.projectRoot,
        aiProvider:     config.aiProvider || 'none',
        aiEnriched:     aiActive,
        scanDurationMs: Date.now() - startTime,
      },
    });
  } catch (err) {
    console.error('[server] Audit failed:', err);
    res.status(500).json({ error: err.message });
  } finally {
    isRunning = false;
  }
});

// ── Persist a key=value pair into .env ──────────────────────────────────────
function saveKeyToEnv(key, value) {
  const envPath = path.join(__dirname, '.env');
  let content = '';
  try { content = readFileSync(envPath, 'utf8'); } catch { /* no .env yet */ }
  const lines = content.split('\n');
  const idx = lines.findIndex(l => l.startsWith(`${key}=`));
  if (idx >= 0) lines[idx] = `${key}=${value}`;
  else lines.push(`${key}=${value}`);
  writeFileSync(envPath, lines.join('\n'), 'utf8');
}

// ── AI provider selection prompt ────────────────────────────────────────────
async function selectAIProvider() {
  // If pre-configured via env var, use it directly
  if (config.aiProvider) return;

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  console.log('\n  ┌─────────────────────────────────────────┐');
  console.log('  │         Enriquecimiento con IA          │');
  console.log('  └─────────────────────────────────────────┘\n');
  console.log('    [1] Claude (Anthropic)');
  console.log('    [2] OpenAI (GPT-4o)');
  console.log('    [3] Sin IA — solo análisis estático\n');

  const ans = await ask('  Selecciona proveedor [1/2/3]: ');
  const choice = ans.trim() === '2' ? 'openai' : ans.trim() === '3' ? 'none' : 'claude';

  if (choice === 'claude' && !config.anthropicApiKey) {
    const key = await ask('  ANTHROPIC_API_KEY: ');
    const trimmed = key.trim();
    if (trimmed) { config.anthropicApiKey = trimmed; saveKeyToEnv('ANTHROPIC_API_KEY', trimmed); }
    else { console.log('  Sin key — usando modo sin IA.\n'); config.aiProvider = 'none'; rl.close(); return; }
  }

  if (choice === 'openai' && !config.openaiApiKey) {
    const key = await ask('  OPENAI_API_KEY: ');
    const trimmed = key.trim();
    if (trimmed) { config.openaiApiKey = trimmed; saveKeyToEnv('OPENAI_API_KEY', trimmed); }
    else { console.log('  Sin key — usando modo sin IA.\n'); config.aiProvider = 'none'; rl.close(); return; }
  }

  config.aiProvider = choice;
  rl.close();
}

// ── Start ───────────────────────────────────────────────────────────────────
await selectAIProvider();

app.listen(config.port, async () => {
  const structure = await discoverStructure();
  const providerLabel = {
    claude: '✓ Claude (Anthropic) — deep/full modes',
    openai: '✓ OpenAI (GPT-4o) — deep/full modes',
    none:   '✗ Sin IA (solo análisis estático)',
  }[config.aiProvider] || '✗ Sin IA';

  console.log(`\n  ███████╗██████╗  █████╗  ██████╗████████╗██╗ █████╗`);
  console.log(`  ██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔══██╗`);
  console.log(`  █████╗  ██████╔╝███████║██║        ██║   ██║███████║`);
  console.log(`  ██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██║██╔══██║`);
  console.log(`  ██║     ██║  ██║██║  ██║╚██████╗   ██║   ██║██║  ██║`);
  console.log(`  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝╚═╝  ╚═╝\n`);
  console.log(`  Security Audit Tool — v2.0.0`);
  console.log(`  ─────────────────────────────────────────`);
  console.log(`  UI:           http://localhost:${config.port}`);
  console.log(`  Project:      ${config.projectRoot}`);
  console.log(`  Framework:    ${structure.framework} (src: ${structure.srcDir})`);
  console.log(`  IA:           ${providerLabel}`);
  console.log(`  ─────────────────────────────────────────\n`);
});
