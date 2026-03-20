import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from './config.js';
import { enrichWithClaude } from './utils/claudeClient.js';
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
    claudeEnabled: !!config.anthropicApiKey,
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

    // Phase 2: Enrich with Claude (deep/full modes only, if API key available)
    if (depth !== 'standard' && config.anthropicApiKey) {
      try {
        await enrichWithClaude(auditResults, depth);
      } catch (err) {
        console.warn('[Claude] Enrichment failed:', err.message);
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
        claudeEnriched: depth !== 'standard' && !!config.anthropicApiKey,
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

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(config.port, async () => {
  const structure = await discoverStructure();
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
  console.log(`  Claude AI:    ${config.anthropicApiKey ? '✓ enabled (deep/full modes)' : '✗ not configured (set ANTHROPIC_API_KEY)'}`);
  console.log(`  ─────────────────────────────────────────\n`);
});
