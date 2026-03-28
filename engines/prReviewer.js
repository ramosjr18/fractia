/**
 * PR Reviewer — Shift-Left Security Gate
 *
 * Flujo:
 *  1. Descarga los archivos modificados en un PR de GitHub
 *  2. Ejecuta el Code Audit de Fractia sobre esos archivos
 *  3. Publica un PR Review en GitHub:
 *     - REQUEST_CHANGES si hay critical/high
 *     - COMMENT si solo hay medium/low
 *
 * Uso:
 *   CLI:  fractia review-pr --repo owner/repo --pr 42
 *   Code: import { reviewPR } from './engines/prReviewer.js';
 */
import path from 'path';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { config }           from '../config.js';
import { runCodeAudit }     from './codeAudit.js';
import { GitHubClient, parseRepo } from '../utils/githubClient.js';

// File extensions worth auditing
const AUDIT_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py']);

// ── PR review body ─────────────────────────────────────────────────────────────
function buildReviewBody({ results, riskScore, prTitle, fileCount }) {
  const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', ok: '🟢' };
  const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };

  // Summary line
  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) counts[r.severity] = (counts[r.severity] || 0) + 1;

  const worst = results.reduce(
    (w, r) => SEV_RANK[r.severity] > SEV_RANK[w] ? r.severity : w, 'ok'
  );

  const verdict =
    worst === 'critical' ? '🔴 **BLOQUEADO** — vulnerabilidades críticas detectadas' :
    worst === 'high'     ? '🟠 **CAMBIOS REQUERIDOS** — hallazgos de severidad alta' :
    worst === 'medium'   ? '🟡 **REVISAR** — hallazgos de severidad media' :
                           '🟢 **APROBADO** — sin hallazgos críticos ni altos';

  // Modules section
  const moduleRows = results
    .filter(r => r.findings.length > 0)
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
    .map(r => {
      const top = r.findings
        .slice(0, 3)
        .map(f => `  - **${(f.type || '').toUpperCase()}**: ${f.title}`)
        .join('\n');
      return `#### ${SEV_EMOJI[r.severity]} ${r.name} \`[${r.severity}]\`\n${top}`;
    })
    .join('\n\n');

  return `## 🛡️ Fractia Security Review — PR: ${prTitle}

${verdict}

**Risk score:** ${riskScore}/100 | **Archivos analizados:** ${fileCount} | **Módulos con hallazgos:** ${results.filter(r => r.findings.length > 0).length}

---
${moduleRows || '_Sin hallazgos en los archivos modificados._'}

---
<details>
<summary>Conteo por severidad</summary>

| Severidad | Módulos |
|-----------|---------|
| 🔴 Critical | ${counts.critical} |
| 🟠 High | ${counts.high} |
| 🟡 Medium | ${counts.medium} |
| 🔵 Low | ${counts.low} |
| 🟢 OK | ${counts.ok} |

</details>

_Análisis automático por [Fractia](https://github.com/your-org/fractia) v3.0.0 — Code Audit (standard depth)_`;
}

// ── Main reviewer ─────────────────────────────────────────────────────────────
/**
 * @param {object}  options
 * @param {string}  options.repo          - "owner/repo"
 * @param {number}  options.prNumber
 * @param {string}  options.githubToken
 * @param {boolean} [options.postReview]  - default true; set false for dry-run
 * @param {object}  [options.hooks]       - { onInfo, onFileDownloaded, onModuleComplete, onReviewPosted }
 * @returns {Promise<{ pr, results, riskScore, worstSeverity, reviewUrl, reviewEvent }>}
 */
export async function reviewPR({ repo, prNumber, githubToken, postReview = true, hooks = {} }) {
  const { owner, repo: repoName } = parseRepo(repo);
  const gh = new GitHubClient(githubToken);

  // ── 1. PR info + files ────────────────────────────────────────────────────
  const [pr, files] = await Promise.all([
    gh.getPR(owner, repoName, prNumber),
    gh.getPRFiles(owner, repoName, prNumber),
  ]);

  const headSha     = pr.head.sha;
  const prTitle     = pr.title;
  const auditableFiles = files.filter(f =>
    AUDIT_EXTS.has(path.extname(f.filename)) && f.status !== 'removed'
  );

  hooks.onInfo?.({
    title:    prTitle,
    author:   pr.user.login,
    branch:   pr.head.ref,
    files:    files.length,
    auditing: auditableFiles.length,
  });

  if (auditableFiles.length === 0) {
    hooks.onInfo?.({ note: 'Sin archivos auditables — PR omitida' });
    return { pr, results: [], riskScore: 0, worstSeverity: 'ok', reviewUrl: null, reviewEvent: 'COMMENT' };
  }

  // ── 2. Download changed files to temp dir ─────────────────────────────────
  const tmpDir = `/tmp/fractia-pr-${prNumber}-${Date.now()}`;
  mkdirSync(tmpDir, { recursive: true });

  const downloaded = [];
  for (const f of auditableFiles) {
    try {
      const content = await gh.getFileContent(owner, repoName, f.filename, headSha);
      const dest = path.join(tmpDir, f.filename);
      mkdirSync(path.dirname(dest), { recursive: true });
      writeFileSync(dest, content, 'utf8');
      downloaded.push(f.filename);
      hooks.onFileDownloaded?.({ file: f.filename });
    } catch (e) {
      // File may not exist at that ref (e.g. submodule) — skip silently
    }
  }

  if (downloaded.length === 0) {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    throw new Error('No se pudo descargar ningún archivo del PR');
  }

  // ── 3. Run Code Audit on temp dir ─────────────────────────────────────────
  const savedRoot      = config.projectRoot;
  config.projectRoot   = tmpDir;

  let results, riskScore;
  try {
    const audit = await runCodeAudit(
      ['auth', 'api', 'sql', 'xss', 'secrets', 'headers', 'bots', 'crypto', 'logs'],
      'standard',
      { onModuleComplete: (mod, result, ms) => hooks.onModuleComplete?.({ mod, result, ms }) }
    );
    results   = audit.results;
    riskScore = audit.riskScore;
  } finally {
    config.projectRoot = savedRoot;
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }

  // ── 4. Determine verdict ──────────────────────────────────────────────────
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const worstSeverity = results.reduce(
    (w, r) => SEV_RANK[r.severity] > SEV_RANK[w] ? r.severity : w, 'ok'
  );

  const reviewEvent =
    ['critical', 'high'].includes(worstSeverity) ? 'REQUEST_CHANGES' : 'COMMENT';

  // ── 5. Post review to GitHub ──────────────────────────────────────────────
  let reviewUrl = null;
  if (postReview) {
    const body   = buildReviewBody({ results, riskScore, prTitle, fileCount: downloaded.length });
    const review = await gh.createPRReview(owner, repoName, prNumber, {
      body,
      event: reviewEvent,
      comments: [],
    });
    reviewUrl = review.html_url || `https://github.com/${owner}/${repoName}/pull/${prNumber}`;
    hooks.onReviewPosted?.({ url: reviewUrl, event: reviewEvent });
  }

  return { pr, results, riskScore, worstSeverity, reviewUrl, reviewEvent };
}
