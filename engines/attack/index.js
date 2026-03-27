/**
 * Fractia Attack Engine — Pilar C: Pentesting Activo / DAST
 * Registry of attack profiles + shared runner + report saver
 */
import path from 'path';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Profile registry ──────────────────────────────────────────────────────────
export const PROFILES = {
  'slowloris':     () => import('./profiles/slowloris.js'),
  'bots-stuffing': () => import('./profiles/botsStuffing.js'),
};

export const PROFILE_LIST = [
  {
    id:          'slowloris',
    name:        'Slowloris',
    description: 'Connection exhaustion — agota el pool de conexiones del servidor',
    risk:        'medium',
    requiredOpts: [],
  },
  {
    id:          'bots-stuffing',
    name:        'Credential Stuffing',
    description: 'Ráfaga de logins falsos para validar rate limiting y lockout',
    risk:        'medium',
    requiredOpts: ['loginPath'],
  },
];

/**
 * Run an attack profile.
 * @param {string}   profile  - profile id
 * @param {string}   target   - target URL
 * @param {object}   opts     - profile-specific options
 * @param {object}   hooks    - { onStart, onProgress, onTick, onRequest, onBatch, onProbe, onAllOpen }
 */
export async function runAttack({ profile, target, opts = {}, hooks = {} }) {
  const loader = PROFILES[profile];
  if (!loader) throw new Error(`Perfil desconocido: "${profile}". Disponibles: ${Object.keys(PROFILES).join(', ')}`);

  const { run } = await loader();
  return await run({ target, opts, hooks });
}

/**
 * Save attack result to reports/
 */
export function saveAttackReport({ result, target, projectName }) {
  const reportsDir = path.join(__dirname, '..', '..', 'reports');
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });

  const ts       = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const proj     = (projectName || 'attack').replace(/[^a-z0-9_-]/gi, '_');
  const filename = `${proj}_attack_${result.profile}_${ts}.json`;
  const filepath = path.join(reportsDir, filename);

  const report = {
    meta: {
      tool:        'Fractia v3.0.0 — Pilar C DAST',
      profile:     result.profile,
      target,
      generatedAt: new Date().toISOString(),
      severity:    result.severity,
    },
    verdict:         result.verdict,
    severity:        result.severity,
    stats:           result.stats,
    probes:          result.probes || [],
    recommendations: result.recommendations,
  };

  writeFileSync(filepath, JSON.stringify(report, null, 2), 'utf8');
  return filepath;
}
