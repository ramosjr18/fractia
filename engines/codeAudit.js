/**
 * Code Audit Engine — shared between CLI and web server
 */
import { config } from '../config.js';
import { enrichWithClaude } from '../utils/claudeClient.js';
import { enrichWithOpenAI } from '../utils/openaiClient.js';

export const ALL_MODULES = [
  'auth', 'api', 'ddos', 'sql', 'xss', 'secrets',
  'headers', 'deps', 'infra', 'bots', 'crypto', 'logs', 'nextjs',
];

const AUDITORS = {
  auth:    () => import('../auditors/auth.js'),
  api:     () => import('../auditors/api.js'),
  ddos:    () => import('../auditors/ddos.js'),
  sql:     () => import('../auditors/sql.js'),
  xss:     () => import('../auditors/xss.js'),
  secrets: () => import('../auditors/secrets.js'),
  headers: () => import('../auditors/headers.js'),
  deps:    () => import('../auditors/deps.js'),
  infra:   () => import('../auditors/infra.js'),
  bots:    () => import('../auditors/bots.js'),
  crypto:  () => import('../auditors/crypto.js'),
  logs:    () => import('../auditors/logs.js'),
  nextjs:  () => import('../auditors/nextjs.js'),
};

const WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, ok: 0 };

export function calculateRiskScore(results) {
  return Math.min(100, results.reduce((sum, r) => sum + (WEIGHTS[r.severity] || 0), 0));
}

export function generateSummary(results, riskScore) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) counts[r.severity] = (counts[r.severity] || 0) + 1;

  const criticalMods = results.filter(r => r.severity === 'critical').map(r => r.name);
  const highMods     = results.filter(r => r.severity === 'high').map(r => r.name);

  let summary = `Risk score ${riskScore}/100 across ${results.length} modules. `;
  if (counts.critical > 0) summary += `CRITICAL issues in: ${criticalMods.join(', ')}. `;
  if (counts.high > 0)     summary += `HIGH severity in: ${highMods.join(', ')}. `;
  if (counts.critical === 0 && counts.high === 0) summary += 'No critical or high severity issues. ';
  summary += `${counts.ok} modules passed cleanly.`;
  return summary;
}

/**
 * Run a code audit.
 * @param {string[]} modules  - module names to run
 * @param {string}   depth    - 'standard' | 'deep' | 'full'
 * @param {object}   hooks    - { onModuleStart, onModuleComplete }
 * @returns {{ results, riskScore, summary, meta }}
 */
export async function runCodeAudit(modules, depth = 'standard', hooks = {}) {
  const validModules = modules.filter(m => AUDITORS[m]);
  const startTime    = Date.now();

  const auditResults = await Promise.all(
    validModules.map(async (mod) => {
      const t0 = Date.now();
      hooks.onModuleStart?.(mod);
      try {
        const { audit } = await AUDITORS[mod]();
        const result = await audit(depth);
        hooks.onModuleComplete?.(mod, result, Date.now() - t0);
        return result;
      } catch (err) {
        const errResult = {
          id: mod, name: mod, severity: 'low', score: 100,
          findings: [{ type: 'info', title: 'Auditor error', description: err.message, code_example: null, cve: null }],
          recommendations: [],
          _error: true,
        };
        hooks.onModuleComplete?.(mod, errResult, Date.now() - t0);
        return errResult;
      }
    })
  );

  // AI enrichment (deep/full only)
  const aiActive = depth !== 'standard' && config.aiProvider && config.aiProvider !== 'none';
  if (aiActive) {
    try {
      if (config.aiProvider === 'openai') await enrichWithOpenAI(auditResults, depth);
      else if (config.aiProvider === 'claude') await enrichWithClaude(auditResults, depth);
    } catch (err) {
      console.warn(`[${config.aiProvider}] Enrichment failed:`, err.message);
    }
  }

  const cleanResults = auditResults.map(({ _codeSnippets, _error, ...r }) => r);
  const riskScore    = calculateRiskScore(cleanResults);
  const summary      = generateSummary(cleanResults, riskScore);

  return {
    results: cleanResults,
    riskScore,
    summary,
    meta: {
      generatedAt:    new Date().toISOString(),
      engine:         'code',
      depth,
      projectRoot:    config.projectRoot,
      aiProvider:     config.aiProvider || 'none',
      aiEnriched:     aiActive,
      scanDurationMs: Date.now() - startTime,
    },
  };
}
